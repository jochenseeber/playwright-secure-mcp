require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::PageUrl do
  let(reader) { PlaywrightSecureMcp::PageUrl.new }

  private def result_with(text : String) : JSON::Any
    content = [JSON::Any.new({"type" => JSON::Any.new("text"), "text" => JSON::Any.new(text)})]
    JSON::Any.new({"result" => JSON::Any.new({"content" => JSON::Any.new(content)})})
  end

  it "asks upstream to evaluate location.href and returns the url" do
    seen = nil.as(JSON::Any?)
    url = reader.current do |params|
      seen = params
      result_with("https://example.com/login")
    end
    expect(url).to eq("https://example.com/login")
    # ameba:disable Lint/NotNil
    expect(seen.not_nil!["name"].as_s).to eq("browser_evaluate")
    # ameba:disable Lint/NotNil
    expect(seen.not_nil!["arguments"]["function"].as_s).to eq("() => location.href")
  end

  it "extracts the url from a JSON-quoted reply" do
    url = reader.current { |_| result_with(%("https://example.com/login")) }
    expect(url).to eq("https://example.com/login")
  end

  it "extracts the url from a markdown-wrapped reply" do
    text = <<-MARKDOWN
      ### Result
      ```
      "https://example.com/login"
      ```

      ### Ran Playwright code
      ```js
      await page.evaluate('() => location.href');
      ```
      MARKDOWN
    url = reader.current { |_| result_with(text) }
    expect(url).to eq("https://example.com/login")
  end

  it "raises when a markdown reply contains no url" do
    text = <<-MARKDOWN
      ### Result
      ```
      undefined
      ```

      ### Ran Playwright code
      ```js
      await page.evaluate('() => location.href');
      ```
      MARKDOWN
    expect do
      reader.current { |_| result_with(text) }
    end.to raise_error(PlaywrightSecureMcp::PageUrl::UnavailableError)
  end

  it "raises when the url cannot be determined" do
    expect do
      reader.current { |_| result_with("   ") }
    end.to raise_error(PlaywrightSecureMcp::PageUrl::UnavailableError)
  end

  it "raises when the tool result signals an error, even if it contains a url" do
    content = [JSON::Any.new({"type" => JSON::Any.new("text"), "text" => JSON::Any.new("Error: navigation to https://example.com/login failed")})]
    response = JSON::Any.new({
      "result" => JSON::Any.new({
        "isError" => JSON::Any.new(true),
        "content" => JSON::Any.new(content),
      }),
    })
    expect do
      reader.current { |_| response }
    end.to raise_error(PlaywrightSecureMcp::PageUrl::UnavailableError)
  end

  it "raises when the upstream response is not a JSON object" do
    expect do
      reader.current { |_| JSON.parse(%("garbage")) }
    end.to raise_error(PlaywrightSecureMcp::PageUrl::UnavailableError)
  end
end
