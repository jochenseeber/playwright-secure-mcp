require "./spec_helper"
require "../src/playwright_secure_mcp/item_cache"
require "../src/playwright_secure_mcp/redactor"

Spectator.describe PlaywrightSecureMcp::Redactor do
  let(cache) { PlaywrightSecureMcp::ItemCache.new }
  let(redactor) { PlaywrightSecureMcp::Redactor.new(cache) }

  it "redacts the raw secret value" do
    cache.add_loose_secret("s3cr3t&value")
    expect(redactor.redact("token=s3cr3t&value end")).to eq("token=«REDACTED» end")
  end

  it "redacts the URL-encoded form" do
    cache.add_loose_secret("a b&c")
    encoded = URI.encode_www_form("a b&c")
    expect(redactor.redact("q=#{encoded}")).to eq("q=«REDACTED»")
  end

  it "redacts the Base64 form" do
    cache.add_loose_secret("hunter2")
    encoded = Base64.strict_encode("hunter2")
    expect(redactor.redact("blob:#{encoded}")).to eq("blob:«REDACTED»")
  end

  it "redacts the HTML-escaped form" do
    cache.add_loose_secret(%(<a>&"))
    escaped = HTML.escape(%(<a>&"))
    expect(redactor.redact("body #{escaped} tail")).to eq("body «REDACTED» tail")
  end

  it "leaves unrelated text untouched" do
    cache.add_loose_secret("secret")
    expect(redactor.redact("nothing to see")).to eq("nothing to see")
  end

  it "redacts within JSON string leaves and keeps the structure valid" do
    cache.add_loose_secret("hunter2")
    message = JSON.parse(%({"id":1,"result":{"content":[{"text":"pw=hunter2"},{"text":"safe"}]}}))
    redacted = redactor.redact(message)
    # Re-serializing still yields parseable JSON, and the leaf secret is gone.
    reparsed = JSON.parse(redacted.to_json)
    expect(reparsed["result"]["content"].as_a.first["text"].as_s).to eq("pw=«REDACTED»")
    expect(reparsed["id"].as_i).to eq(1)
  end

  it "does not corrupt JSON when a cached secret is a structural character" do
    # A short/structural field value (e.g. a test password of ",") must not
    # turn a client-bound response into unparseable JSON — that desyncs the
    # client's stream and wedges every later call.
    cache.add_loose_secret(",")
    message = JSON.parse(%({"id":7,"result":[{"item":"a"},{"item":"b"}]}))
    redacted = redactor.redact(message)
    reparsed = JSON.parse(redacted.to_json) # must not raise
    expect(reparsed["result"].as_a.map(&.["item"].as_s)).to eq(["a", "b"])
    expect(reparsed["id"].as_i).to eq(7)
  end
end
