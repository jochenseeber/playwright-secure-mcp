{% if flag?(:linux) %}
  require "random/secure"
  require "./secret_cipher"
  require "./encrypted_secret"

  module PlaywrightSecureMcp
    # Stores a 32-byte AES-256 data key K in the kernel keyring (not process
    # memory) and runs AES-256-CBC via a kernel AF_ALG socket bound to that key
    # by serial number. K is generated, handed to the kernel via `add_key(2)`,
    # and zeroed in this process immediately afterwards; every subsequent
    # crypto operation asks the kernel to do the AES itself, so K never
    # re-enters process memory for the lifetime of this object.
    #
    # `add_key(2)` has no glibc wrapper and is invoked as a raw syscall via
    # `LibC.syscall`. The kernel's raw `skcipher` transform performs no
    # padding, so this class applies PKCS#7 padding itself before handing
    # blocks to AF_ALG (mirrors what OpenSSL's `aes-256-cbc` does for the
    # other tiers, so `EncryptedSecret` round-trips arbitrary-length input).
    #
    # ABI WARNING: `SYS_add_key`, the `sockaddr_alg`/`af_alg_iv` struct
    # layouts, and the cmsg buffer construction below are ported by hand from
    # the Linux UAPI headers and man pages and CANNOT be exercised on this
    # (macOS) build host -- only cross-compiled and type-checked. See the
    # accompanying report for citations and what must be re-verified on a
    # Linux >= 5.4 host.
    class KeyringCipher < SecretCipher
      class Error < Exception
      end

      DATA_KEY_SIZE = 32
      IV_SIZE       = 16
      BLOCK_SIZE    = 16

      # `SYS_add_key` syscall numbers. There is no glibc wrapper for
      # `add_key(2)`, so it is invoked directly via `LibC.syscall`.
      #   x86_64: arch/x86/entry/syscalls/syscall_64.tbl -> 248
      #   arm64:  include/uapi/asm-generic/unistd.h (generic table) -> 217
      SYS_ADD_KEY = {% if flag?(:x86_64) %}
                      248_i64
                    {% elsif flag?(:aarch64) %}
                      217_i64
                    {% else %}
                      {% raise "KeyringCipher: SYS_add_key syscall number is not known for this architecture" %}
                    {% end %}

      # KEY_SPEC_PROCESS_KEYRING (linux/keyctl.h): the kernel creates the
      # process keyring on first use if it does not already exist.
      KEY_SPEC_PROCESS_KEYRING = -2_i64

      # linux/socket.h: AF_ALG = 38 (algorithm sockets).
      AF_ALG = 38

      # linux/if_alg.h: SOL_ALG = 279 (setsockopt level for AF_ALG sockets).
      SOL_ALG = 279
      # ALG_SET_KEY_BY_KEY_SERIAL requires Linux >= 5.4; binds the transform
      # to a key already resident in a kernel keyring, by serial number.
      ALG_SET_KEY_BY_KEY_SERIAL = 7
      # linux/if_alg.h cmsg types carried on the per-operation socket.
      ALG_SET_OP     = 3
      ALG_SET_IV     = 2
      ALG_OP_DECRYPT = 0_u32
      ALG_OP_ENCRYPT = 1_u32

      # linux/if_alg.h:
      #   struct sockaddr_alg {
      #     __u16 salg_family;    /* = AF_ALG */
      #     __u8  salg_type[14];  /* "skcipher" */
      #     __u32 salg_feat;
      #     __u32 salg_mask;
      #     __u8  salg_name[64];  /* "cbc(aes)" */
      #   };
      # sizeof == 88 (2 + 14 + 4 + 4 + 64, no padding: every multi-byte field
      # already falls on a 4-byte boundary). Declared in its own `lib` block
      # (not `LibC`) purely to hold this struct; `bind(2)` takes a generic
      # `LibC::Sockaddr*`, so a pointer to this struct is cast to that type --
      # layout-compatible because `salg_family` occupies the same leading
      # bytes as `sa_family`.
      lib LibAfAlg
        struct SockaddrAlg
          salg_family : UInt16
          salg_type : UInt8[14]
          salg_feat : UInt32
          salg_mask : UInt32
          salg_name : UInt8[64]
        end
      end

      @serial : Int32
      @alg_fd : Int32

      # Adds a fresh random data key to the kernel keyring and opens an AF_ALG
      # cbc(aes) transform bound to it by serial. Raises Error if any step is
      # unsupported (missing AF_ALG module, kernel < 5.4 for
      # ALG_SET_KEY_BY_KEY_SERIAL, etc.) -- this drives CipherSelector's
      # fallback to the next tier.
      def initialize
        key = Random::Secure.random_bytes(DATA_KEY_SIZE)
        begin
          @serial = add_key(key)
        ensure
          key.fill(0_u8)
        end
        @alg_fd = open_alg_socket(@serial)
      end

      def encrypt(plaintext : Bytes) : EncryptedSecret
        iv = Random::Secure.random_bytes(IV_SIZE)
        ciphertext = transform(ALG_OP_ENCRYPT, iv, pkcs7_pad(plaintext))
        EncryptedSecret.new(iv: iv, ciphertext: ciphertext)
      end

      def decrypt(entry : EncryptedSecret) : Bytes
        pkcs7_unpad(transform(ALG_OP_DECRYPT, entry.iv, entry.ciphertext))
      end

      def decrypt_batch(entries : Array(EncryptedSecret)) : Array(Bytes)
        entries.map { |entry| decrypt(entry) }
      end

      def description : String
        "kernel keyring"
      end

      # Adds +payload+ to the process keyring under the "user" key type,
      # returning the kernel-assigned key serial. All variadic arguments are
      # explicitly widened to a full 64-bit register value (pointers already
      # are; KEY_SPEC_PROCESS_KEYRING is passed as Int64) rather than relying
      # on C's variadic integer-promotion rules, because the raw syscall
      # trampoline reads full 64-bit registers with no prototype to guide
      # narrower-than-register promotion.
      private def add_key(payload : Bytes) : Int32
        type = "user"
        key_description = "playwright-secure-mcp-#{Random::Secure.hex(8)}"
        result = LibC.syscall(
          SYS_ADD_KEY,
          type.to_unsafe.as(Void*),
          key_description.to_unsafe.as(Void*),
          payload.to_unsafe.as(Void*),
          LibC::SizeT.new(payload.size),
          KEY_SPEC_PROCESS_KEYRING,
        )
        raise Error.new("add_key failed: #{Errno.value.message}") if result < 0

        result.to_i32
      end

      # Opens an AF_ALG cbc(aes) socket and binds it to the keyring-resident
      # key by serial (requires Linux >= 5.4). The bound socket (@alg_fd) is
      # kept open for the process lifetime; one `accept(2)` per crypto op
      # yields a fresh operation fd that is closed after each op.
      private def open_alg_socket(serial : Int32) : Int32
        fd = LibC.socket(AF_ALG, LibC::SOCK_SEQPACKET, 0)
        raise Error.new("socket(AF_ALG) failed: #{Errno.value.message}") if fd < 0

        address = LibAfAlg::SockaddrAlg.new
        address.salg_family = AF_ALG.to_u16
        salg_type = StaticArray(UInt8, 14).new(0_u8)
        "skcipher".to_slice.copy_to(salg_type.to_unsafe, 8)
        address.salg_type = salg_type
        salg_name = StaticArray(UInt8, 64).new(0_u8)
        "cbc(aes)".to_slice.copy_to(salg_name.to_unsafe, 8)
        address.salg_name = salg_name

        if LibC.bind(fd, pointerof(address).as(LibC::Sockaddr*), sizeof(LibAfAlg::SockaddrAlg).to_u32) < 0
          message = Errno.value.message
          LibC.close(fd)
          raise Error.new("bind(AF_ALG cbc(aes)) failed: #{message}")
        end

        serial_value = serial
        if LibC.setsockopt(
             fd, SOL_ALG, ALG_SET_KEY_BY_KEY_SERIAL,
             pointerof(serial_value).as(Void*), sizeof(Int32).to_u32,
           ) < 0
          message = Errno.value.message
          LibC.close(fd)
          raise Error.new("setsockopt(ALG_SET_KEY_BY_KEY_SERIAL) failed (requires Linux >= 5.4): #{message}")
        end

        fd
      end

      # Runs one AES-CBC operation (encrypt or decrypt) through the kernel.
      # `accept(2)`s a fresh operation fd from @alg_fd, sends `input` with two
      # ancillary control messages (ALG_SET_OP, ALG_SET_IV), reads back the
      # same number of bytes, and closes the operation fd.
      private def transform(op : UInt32, iv : Bytes, input : Bytes) : Bytes
        op_fd = LibC.accept(@alg_fd, Pointer(LibC::Sockaddr).null, Pointer(LibC::SocklenT).null)
        raise Error.new("accept(AF_ALG) failed: #{Errno.value.message}") if op_fd < 0

        begin
          control = build_control(op, iv)

          iovec = LibC::Iovec.new
          iovec.iov_base = input.to_unsafe.as(Void*)
          iovec.iov_len = LibC::SizeT.new(input.size)

          message = LibC::Msghdr.new
          message.msg_name = Pointer(Void).null
          message.msg_namelen = 0_u32
          message.msg_iov = pointerof(iovec)
          message.msg_iovlen = LibC::SizeT.new(1)
          message.msg_control = control.to_unsafe.as(Void*)
          message.msg_controllen = LibC::SizeT.new(control.size)
          message.msg_flags = 0

          sent = LibC.sendmsg(op_fd, pointerof(message), 0)
          raise Error.new("sendmsg(AF_ALG) failed: #{Errno.value.message}") if sent < 0

          read_all(op_fd, input.size)
        ensure
          LibC.close(op_fd)
        end
      end

      private def read_all(fd : Int32, size : Int32) : Bytes
        output = Bytes.new(size)
        total_read = 0
        while total_read < size
          chunk = LibC.read(fd, output.to_unsafe + total_read, LibC::SizeT.new(size - total_read))
          raise Error.new("read(AF_ALG) failed: #{Errno.value.message}") if chunk < 0
          break if chunk == 0
          total_read += chunk
        end
        raise Error.new("read(AF_ALG) returned #{total_read}/#{size} bytes") if total_read != size

        output
      end

      # Builds the ancillary-data (cmsg) buffer for one AF_ALG operation: an
      # ALG_SET_OP message (encrypt/decrypt) followed by an ALG_SET_IV message
      # carrying `struct af_alg_iv { __u32 ivlen; __u8 iv[ivlen]; }`
      # (linux/if_alg.h). Offsets are computed by hand from `CMSG_ALIGN` /
      # `CMSG_SPACE` / `CMSG_LEN` (bits/socket.h), aligned to sizeof(size_t)
      # (8 on both x86_64 and aarch64), since Crystal does not expose those
      # macros.
      private def build_control(op : UInt32, iv : Bytes) : Bytes
        op_payload_size = sizeof(UInt32)
        iv_payload_size = sizeof(UInt32) + IV_SIZE
        op_space = cmsg_space(op_payload_size)
        iv_space = cmsg_space(iv_payload_size)

        buffer = Bytes.new(op_space + iv_space)

        op_header = buffer.to_unsafe.as(LibC::Cmsghdr*)
        op_header.value.cmsg_len = LibC::SizeT.new(cmsg_len(op_payload_size))
        op_header.value.cmsg_level = SOL_ALG
        op_header.value.cmsg_type = ALG_SET_OP
        (buffer.to_unsafe + cmsg_align(CMSGHDR_SIZE)).as(UInt32*).value = op

        iv_header = (buffer.to_unsafe + op_space).as(LibC::Cmsghdr*)
        iv_header.value.cmsg_len = LibC::SizeT.new(cmsg_len(iv_payload_size))
        iv_header.value.cmsg_level = SOL_ALG
        iv_header.value.cmsg_type = ALG_SET_IV
        iv_data = buffer.to_unsafe + op_space + cmsg_align(CMSGHDR_SIZE)
        iv_data.as(UInt32*).value = IV_SIZE.to_u32
        iv.copy_to(iv_data + sizeof(UInt32), IV_SIZE)

        buffer
      end

      CMSGHDR_SIZE = sizeof(LibC::Cmsghdr)

      private def cmsg_align(length : Int32) : Int32
        alignment = sizeof(LibC::SizeT)
        (length + alignment - 1) & ~(alignment - 1)
      end

      private def cmsg_space(length : Int32) : Int32
        cmsg_align(CMSGHDR_SIZE) + cmsg_align(length)
      end

      private def cmsg_len(length : Int32) : Int32
        cmsg_align(CMSGHDR_SIZE) + length
      end

      # PKCS#7-pads to BLOCK_SIZE: the kernel's raw `cbc(aes)` transform (via
      # AF_ALG) does no padding of its own, unlike OpenSSL's `aes-256-cbc`
      # used by the other tiers.
      private def pkcs7_pad(data : Bytes) : Bytes
        pad_length = BLOCK_SIZE - (data.size % BLOCK_SIZE)
        padded = Bytes.new(data.size + pad_length, pad_length.to_u8)
        data.copy_to(padded.to_unsafe, data.size)
        padded
      end

      private def pkcs7_unpad(data : Bytes) : Bytes
        raise Error.new("empty AF_ALG output") if data.empty?
        pad_length = data[data.size - 1].to_i
        if pad_length <= 0 || pad_length > BLOCK_SIZE || pad_length > data.size
          raise Error.new("invalid PKCS7 padding")
        end

        data[0, data.size - pad_length]
      end
    end
  end
{% end %}
