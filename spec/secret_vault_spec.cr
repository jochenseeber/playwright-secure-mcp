require "./spec_helper"

# Fake cipher that fails the test if any crypto operation is invoked.
private class ExplodingCipher < PlaywrightSecureMcp::SecretCipher
  def encrypt(plaintext : Bytes) : PlaywrightSecureMcp::EncryptedSecret
    raise "encrypt called"
  end

  def decrypt(entry : PlaywrightSecureMcp::EncryptedSecret) : Bytes
    raise "decrypt called"
  end

  def decrypt_batch(entries : Array(PlaywrightSecureMcp::EncryptedSecret)) : Array(Bytes)
    raise "decrypt_batch called"
  end

  def description : String
    "exploding"
  end
end

Spectator.describe PlaywrightSecureMcp::SecretVault do
  let(vault) { PlaywrightSecureMcp::SecretVault.new }

  it "round-trips a stored secret" do
    vault.store("op://ok/item/field", "super-secret-value")
    expect(vault.fetch("op://ok/item/field")).to eq("super-secret-value")
  end

  it "returns nil for an unknown reference" do
    expect(vault.fetch("op://ok/other/field")).to be_nil
  end

  it "yields every stored plaintext" do
    vault.store("op://ok/a/x", "alpha")
    vault.store("op://ok/b/y", "beta")
    collected = [] of String
    vault.each_plaintext { |secret| collected << secret }
    expect(collected.sort).to eq(["alpha", "beta"])
  end

  it "does not keep the reference or secret in its ciphertext bytes" do
    vault.store("op://ok/item/field", "super-secret-value")
    dumped = [] of String
    vault.each_ciphertext_for_test { |bytes| dumped << bytes.hexstring }
    joined = dumped.join
    expect(joined.includes?("op://ok/item/field".to_slice.hexstring)).to be_false
    expect(joined.includes?("super-secret-value".to_slice.hexstring)).to be_false
  end

  it "does not invoke the cipher when the vault is empty" do
    exploding_vault = PlaywrightSecureMcp::SecretVault.new(ExplodingCipher.new)
    yielded_secrets = [] of String
    exploding_vault.each_plaintext { |secret| yielded_secrets << secret }
    expect(yielded_secrets).to eq([] of String)
  end

  it "overwrites the entry when the same reference is stored again" do
    vault.store("op://ok/item/field", "first")
    vault.store("op://ok/item/field", "second")
    expect(vault.fetch("op://ok/item/field")).to eq("second")
    count = 0
    vault.each_plaintext { |_| count += 1 }
    expect(count).to eq(1)
  end
end
