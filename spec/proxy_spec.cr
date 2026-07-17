require "./spec_helper"

private class FakeUpstream
  getter received_browser_type_text : String?
  getter? received_close : Bool

  def initialize(@transport : PlaywrightSecureMcp::StdioTransport, *,
                 @page_url : String = "https://example.com/login",
                 @fail : Bool = false, @type_hang : Bool = false,
                 @evaluate_blank : Bool = false)
    @received_browser_type_text = nil
    @received_close = false
  end

  def serve : Nil
    spawn do
      while request = @transport.read
        handle(request)
      end
    end
  end

  private def handle(request : JSON::Any) : Nil
    id = request["id"]
    case request["method"].as_s
    when "tools/list"
      tools = [tool("browser_click"), tool("browser_type"), tool("browser_snapshot")]
      reply(id, {"tools" => JSON::Any.new(tools)})
    when "tools/call"
      handle_tool_call(id, request)
    else
      reply(id, {} of String => JSON::Any)
    end
  end

  private def handle_tool_call(id : JSON::Any, request : JSON::Any) : Nil
    arguments = request["params"]["arguments"]
    if request["params"]["name"].as_s == "browser_close"
      @received_close = true
      reply(id, {"content" => JSON::Any.new([text_content("closed")]), "isError" => JSON::Any.new(false)})
      return
    end
    if request["params"]["name"].as_s == "browser_evaluate"
      if @evaluate_blank
        reply(id, {"content" => JSON::Any.new([text_content("")]), "isError" => JSON::Any.new(false)})
      else
        reply(id, {"content" => JSON::Any.new([text_content(@page_url)]), "isError" => JSON::Any.new(false)})
      end
      return
    end
    @received_browser_type_text = arguments["text"]?.try(&.as_s)
    return if @type_hang # simulate an upstream that never answers the forwarded call
    if @fail
      message = "could not type #{arguments["text"].as_s} into target #{arguments["target"]?.try(&.as_s)}"
      reply(id, {"content" => JSON::Any.new([text_content(message)]), "isError" => JSON::Any.new(true)})
    else
      reply(id, {"content" => JSON::Any.new([text_content("typed #{arguments["text"].as_s}")]), "isError" => JSON::Any.new(false)})
    end
  end

  private def tool(name : String) : JSON::Any
    JSON::Any.new({"name" => JSON::Any.new(name)})
  end

  private def text_content(text : String) : JSON::Any
    JSON::Any.new({"type" => JSON::Any.new("text"), "text" => JSON::Any.new(text)})
  end

  private def reply(id : JSON::Any, result : Hash(String, JSON::Any)) : Nil
    message = {"jsonrpc" => JSON::Any.new("2.0"), "id" => id, "result" => JSON::Any.new(result)}
    @transport.write(JSON::Any.new(message))
  end
end

private FAKE_OP_ITEMS = File.expand_path("support/fake_op_items", __DIR__)

private def build_proxy(client, upstream, upstream_timeout : Time::Span = 60.seconds)
  cache = PlaywrightSecureMcp::ItemCache.new
  locator = PlaywrightSecureMcp::ItemLocator.new(op_command: FAKE_OP_ITEMS, account: nil, encryptor: cache)
  finders = [
    PlaywrightSecureMcp::ListItemsFinder.new(
      cache: cache, item_locator: locator, website_matcher: PlaywrightSecureMcp::WebsiteMatcher.new),
    PlaywrightSecureMcp::NameItemsFinder.new(
      cache: cache, item_locator: locator, website_matcher: PlaywrightSecureMcp::WebsiteMatcher.new),
    PlaywrightSecureMcp::TagItemsFinder.new(
      cache: cache, item_locator: locator, website_matcher: PlaywrightSecureMcp::WebsiteMatcher.new),
  ] of PlaywrightSecureMcp::ItemFinder
  PlaywrightSecureMcp::Proxy.new(
    client: client,
    upstream: upstream,
    item_cache: cache,
    item_locator: locator,
    field_selector: PlaywrightSecureMcp::FieldSelector.new,
    page_url: PlaywrightSecureMcp::PageUrl.new,
    website_matcher: PlaywrightSecureMcp::WebsiteMatcher.new,
    redactor: PlaywrightSecureMcp::Redactor.new(cache),
    secret_guard: PlaywrightSecureMcp::SecretGuard.new(cache),
    secret_type_tool: PlaywrightSecureMcp::SecretTypeTool.new,
    finders: finders,
    item_result: PlaywrightSecureMcp::ItemResult.new,
    upstream_timeout: upstream_timeout,
  )
end

private def wired
  client_in_r, client_in_w = IO.pipe
  client_out_r, client_out_w = IO.pipe
  up_in_r, up_in_w = IO.pipe
  up_out_r, up_out_w = IO.pipe
  {
    client_side:    PlaywrightSecureMcp::StdioTransport.new(input: client_in_r, output: client_out_w),
    upstream_side:  PlaywrightSecureMcp::StdioTransport.new(input: up_out_r, output: up_in_w),
    fake_transport: PlaywrightSecureMcp::StdioTransport.new(input: up_in_r, output: up_out_w),
    driver:         PlaywrightSecureMcp::StdioTransport.new(input: client_out_r, output: client_in_w),
    client_in_w:    client_in_w,
  }
end

Spectator.describe PlaywrightSecureMcp::Proxy do
  it "augments tools/list with the secret tools" do
    w = wired
    FakeUpstream.new(w[:fake_transport]).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    w[:driver].write(JSON.parse(%({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}})))
    response = w[:driver].read || raise("no response")
    names = response["result"]["tools"].as_a.map(&.["name"].as_s)
    expect(names.includes?("browser_type_secret")).to be_true
    expect(names.includes?("browser_list_items")).to be_true
    expect(names.includes?("browser_find_items_by_name")).to be_true
    expect(names.includes?("browser_find_items_by_tag")).to be_true
    expect(names.size).to eq(7) # 3 upstream + browser_type_secret + 3 finders
    w[:client_in_w].close
  end

  it "lists the items usable on the current page" do
    w = wired
    FakeUpstream.new(w[:fake_transport]).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"browser_list_items","arguments":{}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["id"].as_i).to eq(12)
    expect(response["result"]["isError"].as_bool).to be_false
    payload = JSON.parse(response["result"]["content"].as_a.first["text"].as_s)
    expect(payload.as_a.first["item"].as_s).to eq("login1")
    labels = payload.as_a.first["fields"].as_a.map(&.["label"].as_s)
    expect(labels.includes?("password")).to be_true
    w[:client_in_w].close
  end

  it "returns no items when the current page matches none" do
    w = wired
    FakeUpstream.new(w[:fake_transport], page_url: "https://other.com/").serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"browser_list_items","arguments":{}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    payload = JSON.parse(response["result"]["content"].as_a.first["text"].as_s)
    expect(payload.as_a.empty?).to be_true
    w[:client_in_w].close
  end

  it "finds items by name" do
    w = wired
    FakeUpstream.new(w[:fake_transport]).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"browser_find_items_by_name","arguments":{"item":"Example"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    payload = JSON.parse(response["result"]["content"].as_a.first["text"].as_s)
    expect(payload.as_a.first["item"].as_s).to eq("login1")
    w[:client_in_w].close
  end

  it "types a cached field, redacting the echoed value" do
    w = wired
    fake = FakeUpstream.new(w[:fake_transport])
    fake.serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    list_call = %({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"browser_list_items","arguments":{}}})
    w[:driver].write(JSON.parse(list_call))
    w[:driver].read || raise("no response")

    call = %({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"v1","item":"login1","field":"password"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(fake.received_browser_type_text).to eq("pw")
    text = response["result"]["content"].as_a.first["text"].as_s
    expect(text).to eq("typed «REDACTED»")
    w[:client_in_w].close
  end

  it "reveals the item on demand when it is not cached yet" do
    w = wired
    fake = FakeUpstream.new(w[:fake_transport])
    fake.serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"v1","item":"login1","field":"password"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(fake.received_browser_type_text).to eq("pw")
    expect(response["result"]["isError"].as_bool).to be_false
    w[:client_in_w].close
  end

  it "refuses to type when the current page is not in the item's URL set" do
    w = wired
    fake = FakeUpstream.new(w[:fake_transport], page_url: "https://evil.com/")
    fake.serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"v1","item":"login1","field":"password"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["result"]["isError"].as_bool).to be_true
    expect(fake.received_browser_type_text.nil?).to be_true
    w[:client_in_w].close
  end

  it "fails closed when the current page URL is unavailable" do
    w = wired
    fake = FakeUpstream.new(w[:fake_transport], evaluate_blank: true)
    fake.serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"v1","item":"login1","field":"password"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["result"]["isError"].as_bool).to be_true
    expect(fake.received_browser_type_text.nil?).to be_true
    w[:client_in_w].close
  end

  it "returns an isError result when the item cannot be revealed" do
    w = wired
    FakeUpstream.new(w[:fake_transport]).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"v1","item":"missing","field":"password"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["result"]["isError"].as_bool).to be_true
    w[:client_in_w].close
  end

  it "clears the item cache when the client closes the browser" do
    w = wired
    fake = FakeUpstream.new(w[:fake_transport])
    fake.serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    # Populate the cache: the typed secret "pw" is now known and guarded.
    secret_call = %({"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"v1","item":"login1","field":"password"}}})
    w[:driver].write(JSON.parse(secret_call))
    w[:driver].read || raise("no response")

    close_call = %({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"browser_close","arguments":{}}})
    w[:driver].write(JSON.parse(close_call))
    close_response = w[:driver].read || raise("no response")

    # The close is forwarded to the upstream and its reply flows back.
    expect(fake.received_close?).to be_true
    expect(close_response["id"].as_i).to eq(17)
    expect(close_response["result"]["isError"].as_bool).to be_false

    # The cache is gone: the literal "pw" is no longer a known secret, so the
    # guard forwards it and the redactor no longer masks the upstream echo.
    type_call = %({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"browser_type","arguments":{"target":"e1","text":"pw"}}})
    w[:driver].write(JSON.parse(type_call))
    type_response = w[:driver].read || raise("no response")

    expect(type_response["result"]["isError"].as_bool).to be_false
    expect(fake.received_browser_type_text).to eq("pw")
    expect(type_response["result"]["content"].as_a.first["text"].as_s).to eq("typed pw")
    w[:client_in_w].close
  end

  it "returns an isError result instead of hanging when a forwarded upstream call never answers" do
    w = wired
    FakeUpstream.new(w[:fake_transport], type_hang: true).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side], upstream_timeout: 200.milliseconds).run }

    call = %({"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"v1","item":"login1","field":"password"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["id"].as_i).to eq(14)
    expect(response["result"]["isError"].as_bool).to be_true
    w[:client_in_w].close
  end

  it "injects secret-handling instructions into the initialize response" do
    w = wired
    FakeUpstream.new(w[:fake_transport]).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    w[:driver].write(JSON.parse(%({"jsonrpc":"2.0","id":2,"method":"initialize","params":{}})))
    response = w[:driver].read || raise("no response")

    instructions = response["result"]["instructions"].as_s
    expect(instructions.includes?("browser_type_secret")).to be_true
    expect(instructions.includes?("browser_list_items")).to be_true
    expect(instructions.includes?("browser_close")).to be_true
    w[:client_in_w].close
  end

  it "rejects a browser_type call carrying an op:// reference" do
    w = wired
    fake = FakeUpstream.new(w[:fake_transport])
    fake.serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"browser_type","arguments":{"target":"e1","text":"op://vault/item/field"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["result"]["isError"].as_bool).to be_true
    expect(fake.received_browser_type_text.nil?).to be_true
    w[:client_in_w].close
  end

  it "rejects a browser_type call carrying a known revealed secret" do
    w = wired
    fake = FakeUpstream.new(w[:fake_transport])
    fake.serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    secret_call = %({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"v1","item":"login1","field":"password"}}})
    w[:driver].write(JSON.parse(secret_call))
    w[:driver].read || raise("no response")

    leak_call = %({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"browser_type","arguments":{"target":"e1","text":"pw"}}})
    w[:driver].write(JSON.parse(leak_call))
    response = w[:driver].read || raise("no response")

    expect(response["id"].as_i).to eq(5)
    expect(response["result"]["isError"].as_bool).to be_true
    w[:client_in_w].close
  end

  it "logs a redacted diagnostic when the upstream browser_type call fails" do
    backend = Log::MemoryBackend.new
    ::Log.setup(:trace, backend)

    w = wired
    FakeUpstream.new(w[:fake_transport], fail: true).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"v1","item":"login1","field":"password"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["result"]["isError"].as_bool).to be_true
    messages = backend.entries.map(&.message)
    expect(messages.any?(&.includes?("browser_type"))).to be_true
    expect(messages.any?(&.includes?(PlaywrightSecureMcp::Redactor::TOKEN))).to be_true
    expect(messages.none?(&.includes?(%("text":"pw")))).to be_true
    w[:client_in_w].close
  end

  it "forwards a normal browser_type without secrets" do
    w = wired
    fake = FakeUpstream.new(w[:fake_transport])
    fake.serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"browser_type","arguments":{"target":"e1","text":"hello"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["result"]["isError"].as_bool).to be_false
    expect(fake.received_browser_type_text).to eq("hello")
    w[:client_in_w].close
  end
end
