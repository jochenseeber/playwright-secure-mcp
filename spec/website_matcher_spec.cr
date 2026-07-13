require "./spec_helper"

private def item(id : String, *urls : String) : PlaywrightSecureMcp::Item
  PlaywrightSecureMcp::Item.new(vault_id: "v", item_id: id, title: id, urls: urls.to_a)
end

Spectator.describe PlaywrightSecureMcp::WebsiteMatcher do
  let(matcher) { PlaywrightSecureMcp::WebsiteMatcher.new }

  it "matches on exact host ignoring www" do
    items = [item("a", "https://www.example.com"), item("b", "https://other.com")]
    ranked = matcher.rank("https://example.com/login", items)
    expect(ranked.map(&.item_id)).to eq(["a"])
  end

  it "matches a subdomain page against a parent-domain item" do
    items = [item("a", "https://google.com")]
    ranked = matcher.rank("https://accounts.google.com/signin", items)
    expect(ranked.map(&.item_id)).to eq(["a"])
  end

  it "ranks the longest matching path prefix first" do
    items = [item("root", "https://example.com/"), item("admin", "https://example.com/admin")]
    ranked = matcher.rank("https://example.com/admin/login", items)
    expect(ranked.map(&.item_id)).to eq(["admin", "root"])
  end

  it "moves the matched url to the front of the item urls" do
    items = [item("a", "https://example.com/other", "https://example.com/login")]
    ranked = matcher.rank("https://example.com/login", items)
    expect(ranked.first.urls.first).to eq("https://example.com/login")
    expect(ranked.first.urls).to eq(["https://example.com/login", "https://example.com/other"])
  end

  it "does not treat a partial path segment as a prefix match" do
    items = [item("admin", "https://example.com/admin"), item("root", "https://example.com/")]
    ranked = matcher.rank("https://example.com/administrator", items)
    expect(ranked.map(&.item_id)).to eq(["root", "admin"])
  end

  it "matches an item url stored without a scheme" do
    items = [item("bare", "example.com")]
    ranked = matcher.rank("https://example.com/login", items)
    expect(ranked.map(&.item_id)).to eq(["bare"])
  end

  it "returns an empty list when nothing matches" do
    expect(matcher.rank("https://example.com", [item("a", "https://other.com")])).to be_empty
  end

  it "skips an item url that is not a parseable URI instead of raising" do
    items = [item("bad", "http://tiger.local:4080 (MLdonkey)"), item("good", "https://example.com")]
    ranked = matcher.rank("https://example.com/login", items)
    expect(ranked.map(&.item_id)).to eq(["good"])
  end

  it "returns an empty list when the page url itself is unparseable" do
    items = [item("a", "https://example.com")]
    expect(matcher.rank("http://host:not-a-port/x", items)).to be_empty
  end
end
