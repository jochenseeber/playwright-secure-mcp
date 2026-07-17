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

  it "round-trips the service token and reports presence" do
    expect(cache.service_token?).to be_false
    cache.store_service_token("ops_tok_123")
    expect(cache.service_token?).to be_true
    seen = nil.as(String?)
    cache.with_service_token { |token| seen = token }
    expect(seen).to eq("ops_tok_123")
  end

  it "keeps the service token across clear and in each_plaintext" do
    cache.store_service_token("ops_tok_123")
    cache.clear
    expect(cache.service_token?).to be_true
    collected = [] of String
    cache.each_plaintext { |secret| collected << secret }
    expect(collected.includes?("ops_tok_123")).to be_true
  end

  it "does not keep the service token plaintext in ciphertext" do
    cache.store_service_token("ops_tok_123")
    dumped = [] of String
    cache.each_ciphertext_for_test { |bytes| dumped << bytes.hexstring }
    expect(dumped.join.includes?("ops_tok_123".to_slice.hexstring)).to be_false
  end

  it "raises when with_service_token is called with none stored" do
    expect { cache.with_service_token { |_| } }.to raise_error(PlaywrightSecureMcp::ItemCache::Error)
  end
end
