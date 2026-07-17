require "random/secure"
require "./secret_cipher"
require "./encrypted_secret"
require "./aes_cbc"

module PlaywrightSecureMcp
  # Holds the AES key in process memory. Fallback tier and default for tests.
  class InMemoryCipher < SecretCipher
    def initialize(@key : Bytes = Random::Secure.random_bytes(32))
    end

    def encrypt(plaintext : Bytes) : EncryptedSecret
      AesCbc.encrypt(@key, plaintext)
    end

    def decrypt(entry : EncryptedSecret) : Bytes
      AesCbc.decrypt(@key, entry)
    end

    def decrypt_batch(entries : Array(EncryptedSecret)) : Array(Bytes)
      entries.map { |entry| AesCbc.decrypt(@key, entry) }
    end

    def description : String
      "in-memory"
    end
  end
end
