require "./encrypted_secret"

{% if flag?(:darwin) %}
  module PlaywrightSecureMcp
    # AES-256-CBC with a random IV per encryption. Shared by the in-process ciphers.
    #
    # On macOS this uses Apple's CommonCrypto (part of libSystem, so no extra
    # link flag and no libcrypto dependency). The output is byte-compatible
    # with OpenSSL's `aes-256-cbc` (both use PKCS7 padding), matching the
    # Linux build.
    module AesCbc
      # CommonCrypto lives in libSystem, so no @[Link] annotation is needed.
      lib LibCommonCrypto
        fun CCCrypt(op : UInt32, alg : UInt32, options : UInt32,
                    key : UInt8*, key_length : LibC::SizeT,
                    iv : UInt8*, data_in : UInt8*, data_in_length : LibC::SizeT,
                    data_out : UInt8*, data_out_available : LibC::SizeT,
                    data_out_moved : LibC::SizeT*) : Int32
      end

      ENCRYPT_OPERATION = 0_u32 # kCCEncrypt
      DECRYPT_OPERATION = 1_u32 # kCCDecrypt
      AES_ALGORITHM     = 0_u32 # kCCAlgorithmAES
      PKCS7_PADDING     = 1_u32 # kCCOptionPKCS7Padding
      KEY_SIZE          =    32 # kCCKeySizeAES256
      BLOCK_SIZE        =    16 # kCCBlockSizeAES128
      SUCCESS           =     0 # kCCSuccess

      def self.encrypt(key : Bytes, plaintext : Bytes) : EncryptedSecret
        iv = Random::Secure.random_bytes(BLOCK_SIZE)
        ciphertext = crypt(ENCRYPT_OPERATION, key: key, iv: iv, input: plaintext)
        EncryptedSecret.new(iv: iv, ciphertext: ciphertext)
      end

      def self.decrypt(key : Bytes, entry : EncryptedSecret) : Bytes
        crypt(DECRYPT_OPERATION, key: key, iv: entry.iv, input: entry.ciphertext)
      end

      private def self.crypt(operation : UInt32, *, key : Bytes, iv : Bytes, input : Bytes) : Bytes
        output = Bytes.new(input.size + BLOCK_SIZE)
        moved = LibC::SizeT.new(0)
        status = LibCommonCrypto.CCCrypt(operation, AES_ALGORITHM, PKCS7_PADDING,
          key.to_unsafe, LibC::SizeT.new(key.size),
          iv.to_unsafe, input.to_unsafe, LibC::SizeT.new(input.size),
          output.to_unsafe, LibC::SizeT.new(output.size),
          pointerof(moved))
        raise "CommonCrypto CCCrypt failed with status #{status}" unless status == SUCCESS
        output[0, moved]
      end
    end
  end
{% else %}
  require "openssl"
  require "openssl/cipher"

  module PlaywrightSecureMcp
    # AES-256-CBC with a random IV per encryption. Shared by the in-process ciphers.
    module AesCbc
      ALGORITHM = "aes-256-cbc"

      def self.encrypt(key : Bytes, plaintext : Bytes) : EncryptedSecret
        cipher = OpenSSL::Cipher.new(ALGORITHM)
        cipher.encrypt
        cipher.key = key
        iv = cipher.random_iv
        buffer = IO::Memory.new
        buffer.write(cipher.update(plaintext))
        buffer.write(cipher.final)
        EncryptedSecret.new(iv: iv, ciphertext: buffer.to_slice)
      end

      def self.decrypt(key : Bytes, entry : EncryptedSecret) : Bytes
        cipher = OpenSSL::Cipher.new(ALGORITHM)
        cipher.decrypt
        cipher.key = key
        cipher.iv = entry.iv
        buffer = IO::Memory.new
        buffer.write(cipher.update(entry.ciphertext))
        buffer.write(cipher.final)
        buffer.to_slice
      end
    end
  end
{% end %}
