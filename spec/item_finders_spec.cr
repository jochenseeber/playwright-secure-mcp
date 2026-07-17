require "file_utils"
require "./spec_helper"

private FAKE_OP_ITEMS = File.expand_path("support/fake_op_items", __DIR__)

private def build
  cache = PlaywrightSecureMcp::ItemCache.new
  locator = PlaywrightSecureMcp::ItemLocator.new(op_command: FAKE_OP_ITEMS, account: nil, encryptor: cache)
  {cache, locator, PlaywrightSecureMcp::WebsiteMatcher.new}
end

Spectator.describe PlaywrightSecureMcp::ListItemsFinder do
  it "returns and caches login items valid for the current page" do
    cache, locator, matcher = build
    finder = PlaywrightSecureMcp::ListItemsFinder.new(cache: cache, item_locator: locator, website_matcher: matcher)
    items = finder.find("https://example.com/login", JSON.parse("{}"))
    expect(items.map(&.item_id)).to eq(["login1"])
    expect(cache.has?(PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1"))).to be_true
    # fields were revealed
    expect(items.first.fields.empty?).to be_false
  end

  it "drops items whose urls do not match the current page" do
    cache, locator, matcher = build
    finder = PlaywrightSecureMcp::ListItemsFinder.new(cache: cache, item_locator: locator, website_matcher: matcher)
    items = finder.find("https://other.com/", JSON.parse("{}"))
    expect(items.empty?).to be_true
  end

  it "does not re-reveal an already-cached item" do
    directory = File.tempname("finder_reveal_count")
    Dir.mkdir_p(directory)
    counter = File.join(directory, "count")
    script = File.join(directory, "op")
    File.write(script, "#!/bin/sh\n" \
                       "case \"$*\" in *\"item get -\"*) echo revealed >> \"#{counter}\";; esac\n" \
                       "exec \"#{FAKE_OP_ITEMS}\" \"$@\"\n")
    File.chmod(script, 0o755)

    cache = PlaywrightSecureMcp::ItemCache.new
    locator = PlaywrightSecureMcp::ItemLocator.new(op_command: script, account: nil, encryptor: cache)
    finder = PlaywrightSecureMcp::ListItemsFinder.new(
      cache: cache, item_locator: locator, website_matcher: PlaywrightSecureMcp::WebsiteMatcher.new)

    first = finder.find("https://example.com/login", JSON.parse("{}"))
    cached = cache.fetch(PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1"))
    second = finder.find("https://example.com/login", JSON.parse("{}"))

    expect(first.map(&.item_id)).to eq(["login1"])
    expect(second.map(&.item_id)).to eq(["login1"])
    # write-once: the cached item is untouched and the second result is that same entry
    expect(second.first).to eq(cached)
    expect(File.read(counter).lines.size).to eq(1)
  ensure
    FileUtils.rm_rf(directory) if directory
  end
end

Spectator.describe PlaywrightSecureMcp::TagItemsFinder do
  it "returns tagged items usable on the current page" do
    cache, locator, matcher = build
    finder = PlaywrightSecureMcp::TagItemsFinder.new(cache: cache, item_locator: locator, website_matcher: matcher)
    items = finder.find("https://example.com/login", JSON.parse(%({"tag":"work"})))
    expect(items.map(&.item_id)).to eq(["login1"])
    expect(cache.has?(PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1"))).to be_true
  end

  it "returns no items for a tag no login carries" do
    cache, locator, matcher = build
    finder = PlaywrightSecureMcp::TagItemsFinder.new(cache: cache, item_locator: locator, website_matcher: matcher)
    items = finder.find("https://example.com/login", JSON.parse(%({"tag":"nope"})))
    expect(items.empty?).to be_true
  end
end
