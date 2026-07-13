require "./encrypted_secret"

module PlaywrightSecureMcp
  # Encrypts and decrypts cache entries. Implementations differ in where the key
  # lives and where the crypto runs; all produce/consume EncryptedSecret.
  abstract class SecretCipher
    abstract def encrypt(plaintext : Bytes) : EncryptedSecret
    abstract def decrypt(entry : EncryptedSecret) : Bytes
    # Hot path: decrypt many entries under a single key unwrap.
    abstract def decrypt_batch(entries : Array(EncryptedSecret)) : Array(Bytes)
    # Human-readable tier name for the startup log.
    abstract def description : String
  end
end
