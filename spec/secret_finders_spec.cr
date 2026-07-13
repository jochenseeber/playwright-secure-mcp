require "./spec_helper"

private FAKE_OP_LOOKUP = File.expand_path("support/fake_op_lookup", __DIR__)

private def locator : PlaywrightSecureMcp::ItemLocator
  PlaywrightSecureMcp::ItemLocator.new(op_command: FAKE_OP_LOOKUP, account: nil)
end

Spectator.describe "secret finders" do
  it "NameSecretFinder resolves by item argument" do
    finder = PlaywrightSecureMcp::NameSecretFinder.new(locator)
    arguments = JSON.parse(%({"item":"Netflix"}))
    items = finder.find(arguments)
    expect(items.map(&.item_id)).to eq(["item1"])
    expect(finder.name).to eq("browser_find_secret_by_name")
  end

  it "NameSecretFinder raises when the item argument is missing" do
    finder = PlaywrightSecureMcp::NameSecretFinder.new(locator)
    expect { finder.find(JSON.parse(%({}))) }
      .to raise_error(PlaywrightSecureMcp::SecretFinder::MissingArgumentError)
  end

  it "declares the required arguments in each finder definition" do
    name_finder = PlaywrightSecureMcp::NameSecretFinder.new(locator)
    tag_finder = PlaywrightSecureMcp::TagSecretFinder.new(locator)
    url_finder = PlaywrightSecureMcp::UrlSecretFinder.new(
      item_locator: locator,
      website_matcher: PlaywrightSecureMcp::WebsiteMatcher.new,
    )
    expect(name_finder.definition["inputSchema"]["required"].as_a.map(&.as_s)).to eq(["item"])
    expect(tag_finder.definition["inputSchema"]["required"].as_a.map(&.as_s)).to eq(["tag"])
    expect(url_finder.definition["inputSchema"]["required"].as_a.map(&.as_s)).to eq(["url"])
  end

  it "annotates every discovery finder as read-only" do
    finders = [
      PlaywrightSecureMcp::NameSecretFinder.new(locator),
      PlaywrightSecureMcp::TagSecretFinder.new(locator),
      PlaywrightSecureMcp::UrlSecretFinder.new(
        item_locator: locator,
        website_matcher: PlaywrightSecureMcp::WebsiteMatcher.new,
      ),
    ] of PlaywrightSecureMcp::SecretFinder
    finders.each do |finder|
      expect(finder.definition["annotations"]["readOnlyHint"].as_bool).to eq(true)
    end
  end

  it "TagSecretFinder resolves by tag argument" do
    finder = PlaywrightSecureMcp::TagSecretFinder.new(locator)
    items = finder.find(JSON.parse(%({"tag":"apikey"})))
    expect(items.map(&.item_id)).to eq(["item1", "item2"])
  end

  it "UrlSecretFinder ranks logins matching the url argument" do
    finder = PlaywrightSecureMcp::UrlSecretFinder.new(
      item_locator: locator,
      website_matcher: PlaywrightSecureMcp::WebsiteMatcher.new,
    )
    items = finder.find(JSON.parse(%({"url":"https://example.com/login"})))
    expect(items.map(&.item_id)).to eq(["login1"])
  end

  it "UrlSecretFinder raises when the url argument is missing" do
    finder = PlaywrightSecureMcp::UrlSecretFinder.new(
      item_locator: locator,
      website_matcher: PlaywrightSecureMcp::WebsiteMatcher.new,
    )
    expect { finder.find(JSON.parse(%({}))) }
      .to raise_error(PlaywrightSecureMcp::SecretFinder::MissingArgumentError)
  end
end
