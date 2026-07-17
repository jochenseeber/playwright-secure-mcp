require "./spec_helper"
require "../src/playwright_secure_mcp/in_memory_cipher"

Spectator.describe PlaywrightSecureMcp::InMemoryCipher do
  let(cipher) { PlaywrightSecureMcp::InMemoryCipher.new }

  it "round-trips a value" do
    entry = cipher.encrypt("hunter2".to_slice)
    expect(String.new(cipher.decrypt(entry))).to eq("hunter2")
  end

  it "uses a fresh iv per encryption so identical plaintexts differ" do
    a = cipher.encrypt("same".to_slice)
    b = cipher.encrypt("same".to_slice)
    expect(a.ciphertext).not_to eq(b.ciphertext)
  end

  it "decrypts a batch" do
    entries = ["a", "bb", "ccc"].map { |value| cipher.encrypt(value.to_slice) }
    result = cipher.decrypt_batch(entries).map { |bytes| String.new(bytes) }
    expect(result).to eq(["a", "bb", "ccc"])
  end

  it "reports its tier" do
    expect(cipher.description).to eq("in-memory")
  end
end
