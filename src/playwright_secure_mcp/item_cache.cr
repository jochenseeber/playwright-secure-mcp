require "./item"
require "./encrypted_secret"
require "./secret_cipher"
require "./in_memory_cipher"

module PlaywrightSecureMcp
  # In-memory cache of revealed LOGIN items. Field values are encrypted at rest
  # under the process cipher; all other item metadata is kept in the clear.
  # Write-once per key: a re-discovered item is not refreshed until `clear`.
  class ItemCache
    def initialize(@cipher : SecretCipher = InMemoryCipher.new)
      @items = {} of ItemKey => Item
      @loose = [] of EncryptedSecret
      @service_token = nil.as(EncryptedSecret?)
    end

    def encrypt(plaintext : String) : EncryptedSecret
      @cipher.encrypt(plaintext.to_slice)
    end

    def decrypt(entry : EncryptedSecret) : String
      String.new(@cipher.decrypt(entry))
    end

    def store(item : Item) : Nil
      @items[item.key] ||= item
    end

    def fetch(key : ItemKey) : Item?
      @items[key]?
    end

    def has?(key : ItemKey) : Bool
      @items.has_key?(key)
    end

    def clear : Nil
      @items.clear
    end

    # Store a secret that is not part of an item, so the redactor and guard
    # cover it too.
    def add_loose_secret(secret : String) : Nil
      @loose << @cipher.encrypt(secret.to_slice)
    end

    # Stores the 1Password service-account token encrypted at rest. The token
    # survives `clear` and is included in `each_plaintext` for redaction.
    def store_service_token(token : String) : Nil
      @service_token = @cipher.encrypt(token.to_slice)
    end

    def service_token? : Bool
      !@service_token.nil?
    end

    # Decrypts the service token for the duration of the block, zeroing the
    # decrypted bytes afterward. Raises if no token is stored.
    def with_service_token(& : String -> T) : T forall T
      entry = @service_token
      raise "no service-account token stored" if entry.nil?
      bytes = @cipher.decrypt(entry)
      begin
        yield String.new(bytes)
      ensure
        bytes.fill(0_u8)
      end
    end

    def each_plaintext(& : String ->) : Nil
      entries = collect_entries
      return if entries.empty?
      @cipher.decrypt_batch(entries).each { |bytes| yield String.new(bytes) }
    end

    def each_ciphertext_for_test(& : Bytes ->) : Nil
      collect_entries.each { |entry| yield entry.ciphertext }
    end

    private def collect_entries : Array(EncryptedSecret)
      entries = [] of EncryptedSecret
      @items.each_value do |item|
        item.fields.each_value do |field|
          value = field.value
          entries << value unless value.nil?
        end
      end
      entries.concat(@loose)
      token = @service_token
      entries << token unless token.nil?
      entries
    end
  end
end
