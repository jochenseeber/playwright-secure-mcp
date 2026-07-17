{% if flag?(:darwin) %}
  require "random/secure"
  require "./secret_cipher"
  require "./encrypted_secret"
  require "./aes_cbc"

  module PlaywrightSecureMcp
    # Wraps an ephemeral AES-256 data key with a non-extractable P-256 key
    # generated in the Secure Enclave, using ECIES. The data key never touches
    # disk; it is unwrapped in the enclave per crypto op and zeroed afterwards.
    class SecureEnclaveCipher < SecretCipher
      class Error < Exception
      end

      @[Link(framework: "CoreFoundation")]
      lib LibCoreFoundation
        fun CFRelease(cf : Void*) : Void
        fun CFDataCreate(allocator : Void*, bytes : UInt8*, length : LibC::Long) : Void*
        fun CFDataGetLength(the_data : Void*) : LibC::Long
        fun CFDataGetBytePtr(the_data : Void*) : UInt8*
        fun CFDictionaryCreate(
          allocator : Void*,
          keys : Void**,
          values : Void**,
          num_values : LibC::Long,
          key_callbacks : Void*,
          value_callbacks : Void*,
        ) : Void*
        fun CFNumberCreate(allocator : Void*, the_type : Int32, value_ptr : Void*) : Void*
        fun CFErrorCopyDescription(err : Void*) : Void*
        fun CFStringGetCString(the_string : Void*, buffer : UInt8*, buffer_size : LibC::Long, encoding : UInt32) : UInt8

        $kCFTypeDictionaryKeyCallBacks : Void*
        $kCFTypeDictionaryValueCallBacks : Void*
        $kCFBooleanFalse : Void*
      end

      @[Link(framework: "Security")]
      lib LibSecurity
        fun SecKeyCreateRandomKey(parameters : Void*, error : Void**) : Void*
        fun SecKeyCopyPublicKey(key : Void*) : Void*
        fun SecKeyCreateEncryptedData(key : Void*, algorithm : Void*, plaintext : Void*, error : Void**) : Void*
        fun SecKeyCreateDecryptedData(key : Void*, algorithm : Void*, ciphertext : Void*, error : Void**) : Void*

        $kSecAttrKeyType : Void*
        $kSecAttrKeyTypeECSECPrimeRandom : Void*
        $kSecAttrKeySizeInBits : Void*
        $kSecAttrTokenID : Void*
        $kSecAttrTokenIDSecureEnclave : Void*
        $kSecPrivateKeyAttrs : Void*
        $kSecAttrIsPermanent : Void*
        $kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM : Void*
      end

      KCF_NUMBER_SINT32_TYPE   =          3_i32
      KCF_STRING_ENCODING_UTF8 = 0x08000100_u32

      @private_key : Void*
      @wrapped_key : Bytes

      def initialize
        @private_key = create_enclave_key
        public_key = LibSecurity.SecKeyCopyPublicKey(@private_key)
        raise Error.new("SecKeyCopyPublicKey returned null") if public_key.null?

        begin
          data_key = Random::Secure.random_bytes(32)
          begin
            @wrapped_key = ecies_encrypt(public_key, data_key)
          ensure
            data_key.fill(0_u8)
          end
        ensure
          LibCoreFoundation.CFRelease(public_key)
        end
      end

      def encrypt(plaintext : Bytes) : EncryptedSecret
        with_data_key { |key| AesCbc.encrypt(key, plaintext) }
      end

      def decrypt(entry : EncryptedSecret) : Bytes
        with_data_key { |key| AesCbc.decrypt(key, entry) }
      end

      def decrypt_batch(entries : Array(EncryptedSecret)) : Array(Bytes)
        with_data_key { |key| entries.map { |entry| AesCbc.decrypt(key, entry) } }
      end

      def description : String
        "Secure Enclave"
      end

      # Unwraps the data key in the enclave, yields it, then zeroes it.
      private def with_data_key(& : Bytes -> T) : T forall T
        key = ecies_decrypt(@private_key, @wrapped_key)
        begin
          yield key
        ensure
          key.fill(0_u8)
        end
      end

      # Builds the SE key-generation attributes dict and asks Security.framework
      # for a non-extractable P-256 private key backed by the Secure Enclave.
      private def create_enclave_key : Void*
        key_size_value = 256_i32
        key_size = LibCoreFoundation.CFNumberCreate(
          Pointer(Void).null,
          KCF_NUMBER_SINT32_TYPE,
          pointerof(key_size_value).as(Void*),
        )

        private_key_attrs = dictionary({
          LibSecurity.kSecAttrIsPermanent => LibCoreFoundation.kCFBooleanFalse,
        })

        parameters = dictionary({
          LibSecurity.kSecAttrKeyType       => LibSecurity.kSecAttrKeyTypeECSECPrimeRandom,
          LibSecurity.kSecAttrKeySizeInBits => key_size,
          LibSecurity.kSecAttrTokenID       => LibSecurity.kSecAttrTokenIDSecureEnclave,
          LibSecurity.kSecPrivateKeyAttrs   => private_key_attrs,
        })

        error = Pointer(Void).null
        key = LibSecurity.SecKeyCreateRandomKey(parameters, pointerof(error))

        LibCoreFoundation.CFRelease(private_key_attrs)
        LibCoreFoundation.CFRelease(key_size)
        LibCoreFoundation.CFRelease(parameters)

        raise Error.new(cf_error_message(error)) if key.null?

        key
      end

      # Encrypts +plaintext+ with the enclave-backed public key via ECIES,
      # returning the wrapped ciphertext as plain Bytes (non-secret handle data).
      private def ecies_encrypt(public_key : Void*, plaintext : Bytes) : Bytes
        plaintext_data = LibCoreFoundation.CFDataCreate(Pointer(Void).null, plaintext, plaintext.size)
        error = Pointer(Void).null
        wrapped = LibSecurity.SecKeyCreateEncryptedData(
          public_key,
          LibSecurity.kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
          plaintext_data,
          pointerof(error),
        )
        LibCoreFoundation.CFRelease(plaintext_data)

        raise Error.new(cf_error_message(error)) if wrapped.null?

        begin
          cf_data_to_bytes(wrapped)
        ensure
          LibCoreFoundation.CFRelease(wrapped)
        end
      end

      # Decrypts the wrapped data key in the enclave via ECIES.
      private def ecies_decrypt(private_key : Void*, wrapped_key : Bytes) : Bytes
        wrapped_data = LibCoreFoundation.CFDataCreate(Pointer(Void).null, wrapped_key, wrapped_key.size)
        error = Pointer(Void).null
        unwrapped = LibSecurity.SecKeyCreateDecryptedData(
          private_key,
          LibSecurity.kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
          wrapped_data,
          pointerof(error),
        )
        LibCoreFoundation.CFRelease(wrapped_data)

        raise Error.new(cf_error_message(error)) if unwrapped.null?

        begin
          cf_data_to_bytes(unwrapped)
        ensure
          LibCoreFoundation.CFRelease(unwrapped)
        end
      end

      private def cf_data_to_bytes(data : Void*) : Bytes
        length = LibCoreFoundation.CFDataGetLength(data)
        ptr = LibCoreFoundation.CFDataGetBytePtr(data)
        Bytes.new(ptr, length).dup
      end

      # Reads the human-readable message out of a CFErrorRef produced by a
      # failed Security.framework call.
      private def cf_error_message(error : Void*) : String
        return "unknown Security.framework error" if error.null?

        description = LibCoreFoundation.CFErrorCopyDescription(error)
        LibCoreFoundation.CFRelease(error)
        return "unknown Security.framework error" if description.null?

        buffer = Bytes.new(1024)
        ok = LibCoreFoundation.CFStringGetCString(description, buffer, buffer.size, KCF_STRING_ENCODING_UTF8)
        LibCoreFoundation.CFRelease(description)

        ok != 0 ? String.new(buffer.to_unsafe) : "undecodable Security.framework error"
      end

      # Builds a CFDictionary from a Hash of Void* keys/values.
      private def dictionary(entries : Hash(Void*, Void*)) : Void*
        keys = entries.keys
        values = entries.values
        keys_ptr = keys.to_unsafe
        values_ptr = values.to_unsafe
        LibCoreFoundation.CFDictionaryCreate(
          Pointer(Void).null,
          keys_ptr,
          values_ptr,
          entries.size,
          pointerof(LibCoreFoundation.kCFTypeDictionaryKeyCallBacks),
          pointerof(LibCoreFoundation.kCFTypeDictionaryValueCallBacks),
        )
      end
    end
  end
{% end %}
