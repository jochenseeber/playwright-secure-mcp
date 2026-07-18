require "./spec_helper"
require "../src/playwright_secure_mcp/item"
require "../src/playwright_secure_mcp/website_matcher"

private def item(id : String, *urls : String) : PlaywrightSecureMcp::Item
  PlaywrightSecureMcp::Item.new(
    key: PlaywrightSecureMcp::ItemKey.new(vault_id: "v", item_id: id),
    title: id, urls: urls.to_a, tags: [] of String,
    fields: {} of String => PlaywrightSecureMcp::Field,
    sections: {} of String => PlaywrightSecureMcp::Section)
end

Spectator.describe PlaywrightSecureMcp::WebsiteMatcher do
  let(matcher) { PlaywrightSecureMcp::WebsiteMatcher.new }

  it "matches only on the exact host, without folding www" do
    items = [item("a", "https://www.example.com"), item("b", "https://other.com")]
    # www.example.com is a distinct host from example.com now.
    expect(matcher.rank("https://example.com/login", items).map(&.item_id)).to be_empty
    expect(matcher.rank("https://www.example.com/login", items).map(&.item_id)).to eq(["a"])
  end

  it "does not authorize a subdomain page from a parent-domain item" do
    items = [item("a", "https://google.com")]
    expect(matcher.rank("https://accounts.google.com/signin", items)).to be_empty
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
    # /admin does not match /administrator, so only the root item is surfaced.
    expect(ranked.map(&.item_id)).to eq(["root"])
  end

  it "does not rank an item whose path does not match (consistent with matches?)" do
    items = [item("app", "https://example.com/app")]
    expect(matcher.rank("https://example.com/other", items)).to be_empty
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

  it "matches? is true for same host and prefix path, false otherwise" do
    candidate = item("i", "https://example.com/app")
    expect(matcher.matches?("https://example.com/app/login", candidate)).to be_true
    expect(matcher.matches?("https://example.com/other", candidate)).to be_false
    expect(matcher.matches?("https://evil.com/app", candidate)).to be_false
  end

  it "rejects reverse subdomain (child item, parent page)" do
    candidate = item("i", "https://login.example.com")
    expect(matcher.matches?("https://example.com/", candidate)).to be_false
  end

  it "rejects cross-tenant public suffixes" do
    candidate = item("i", "https://github.io")
    expect(matcher.matches?("https://attacker.github.io/x", candidate)).to be_false
  end

  it "requires the page port to match an item url that specifies one" do
    candidate = item("i", "https://example.com:8443")
    expect(matcher.matches?("https://example.com:8443/x", candidate)).to be_true
    expect(matcher.matches?("https://example.com/x", candidate)).to be_false # :443 != :8443
  end

  it "treats an item port equal to the scheme default as matching a portless page" do
    candidate = item("i", "https://example.com:443")
    expect(matcher.matches?("https://example.com/x", candidate)).to be_true
  end

  it "leaves the port unconstrained when the item url has no port" do
    candidate = item("i", "https://example.com")
    expect(matcher.matches?("https://example.com:8443/x", candidate)).to be_true
  end

  it "normalizes a trailing dot on the host" do
    candidate = item("i", "https://example.com.")
    expect(matcher.matches?("https://example.com/x", candidate)).to be_true
  end
end
