require "./item"
require "./encrypted_secret"
require "./secret_cipher"
require "./in_memory_cipher"

module PlaywrightSecureMcp
  # In-memory cache of revealed LOGIN items. Field values are encrypted at rest
  # under the process cipher; all other item metadata is kept in the clear.
  # Write-once per key: a re-discovered item is not refreshed until `clear`.
  class ItemCache
    class Error < Exception
    end

    OTP_TTL = 60.seconds

    private record ExpiringSecret, entry : EncryptedSecret, purge_at : Time

    def initialize(@cipher : SecretCipher = InMemoryCipher.new, *, @clock : Proc(Time) = -> { Time.utc })
      @items = {} of ItemKey => Item
      @loose = [] of EncryptedSecret
      @expiring = [] of ExpiringSecret
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
      @expiring.clear
    end

    # Store a secret that is not part of an item, so the redactor and guard
    # cover it too.
    def add_loose_secret(secret : String) : Nil
      @loose << @cipher.encrypt(secret.to_slice)
    end

    # Stores a secret that is redacted/guarded until purge_expired drops it past
    # OTP_TTL. Used for live one-time-password codes, which are never cached for
    # reuse but must not leak into logs while being typed.
    def add_expiring_secret(secret : String) : Nil
      @expiring << ExpiringSecret.new(@cipher.encrypt(secret.to_slice), @clock.call + OTP_TTL)
    end

    # Drops every expiring secret whose window has closed.
    def purge_expired : Nil
      now = @clock.call
      @expiring.reject! { |entry| now >= entry.purge_at }
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
      raise Error.new("no service-account token stored") if entry.nil?
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
      @expiring.each { |expiring| entries << expiring.entry }
      token = @service_token
      entries << token unless token.nil?
      entries
    end
  end
end
