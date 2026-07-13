require "./sha256"
require "./encrypted_secret"
require "./secret_cipher"
require "./in_memory_cipher"

module PlaywrightSecureMcp
  class SecretVault
    def initialize(@cipher : SecretCipher = InMemoryCipher.new)
      @entries = {} of String => EncryptedSecret
    end

    def fetch(reference : String) : String?
      entry = @entries[digest(reference)]?
      return nil if entry.nil?
      String.new(@cipher.decrypt(entry))
    end

    def store(reference : String, secret : String) : Nil
      @entries[digest(reference)] = @cipher.encrypt(secret.to_slice)
    end

    def each_plaintext(& : String ->) : Nil
      return if @entries.empty?
      @cipher.decrypt_batch(@entries.values).each do |bytes|
        yield String.new(bytes)
      end
    end

    # Test-only introspection to assert the obfuscation guarantee.
    def each_ciphertext_for_test(& : Bytes ->) : Nil
      @entries.each_value { |entry| yield entry.ciphertext }
    end

    private def digest(reference : String) : String
      Sha256.hexdigest(reference)
    end
  end
end
