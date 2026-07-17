require "./spec_helper"
require "../src/playwright_secure_mcp/item"
require "../src/playwright_secure_mcp/item_cache"

private def field(cache, label, value)
  PlaywrightSecureMcp::Field.new(
    id: label, section_id: nil, type: "STRING", purpose: nil,
    label: label, value: value.nil? ? nil : cache.encrypt(value))
end

private def item(cache, vault, id, fields)
  PlaywrightSecureMcp::Item.new(
    key: PlaywrightSecureMcp::ItemKey.new(vault_id: vault, item_id: id),
    title: id, urls: [] of String, tags: [] of String,
    fields: fields, sections: {} of String => PlaywrightSecureMcp::Section)
end

Spectator.describe PlaywrightSecureMcp::ItemCache do
  let(cache) { PlaywrightSecureMcp::ItemCache.new }
  let(key) { PlaywrightSecureMcp::ItemKey.new(vault_id: "v", item_id: "i") }

  it "stores and fetches an item" do
    cache.store(item(cache, "v", "i", {"password" => field(cache, "password", "pw")}))
    fetched = cache.fetch(key)
    expect(fetched.try(&.item_id)).to eq("i")
  end

  it "round-trips a field value through encrypt and decrypt" do
    expect(cache.decrypt(cache.encrypt("pl4in"))).to eq("pl4in")
  end

  it "is write-once: a second store of the same key is ignored" do
    cache.store(item(cache, "v", "i", {"password" => field(cache, "password", "first")}))
    cache.store(item(cache, "v", "i", {"password" => field(cache, "password", "second")}))
    values = [] of String
    cache.each_plaintext { |secret| values << secret }
    expect(values).to eq(["first"])
  end

  it "yields every present field value plus loose secrets" do
    cache.store(item(cache, "v", "i", {
      "u" => field(cache, "username", "alice"),
      "p" => field(cache, "password", "pw"),
      "e" => field(cache, "empty", nil),
    }))
    cache.add_loose_secret("tok")
    got = [] of String
    cache.each_plaintext { |secret| got << secret }
    expect(got.sort).to eq(["alice", "pw", "tok"])
  end

  it "clear drops items but keeps loose secrets" do
    cache.store(item(cache, "v", "i", {"p" => field(cache, "password", "pw")}))
    cache.add_loose_secret("tok")
    cache.clear
    expect(cache.fetch(key)).to be_nil
    got = [] of String
    cache.each_plaintext { |secret| got << secret }
    expect(got).to eq(["tok"])
  end

  it "keeps neither plaintext nor label in ciphertext" do
    cache.store(item(cache, "v", "i", {"p" => field(cache, "password", "super-secret")}))
    dumped = [] of String
    cache.each_ciphertext_for_test { |bytes| dumped << bytes.hexstring }
    expect(dumped.join.includes?("super-secret".to_slice.hexstring)).to be_false
  end
end
