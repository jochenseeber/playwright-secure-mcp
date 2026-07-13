require "./spec_helper"

private class FakeUpstream
  getter received_browser_type_text : String?

  def initialize(@transport : PlaywrightSecureMcp::StdioTransport, @fail : Bool = false, @type_hang : Bool = false)
    @received_browser_type_text = nil
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
      arguments = request["params"]["arguments"]
      @received_browser_type_text = arguments["text"]?.try(&.as_s)
      return if @type_hang # simulate an upstream that never answers the forwarded call
      if @fail
        message = "could not type #{arguments["text"].as_s} into target #{arguments["target"]?.try(&.as_s)}"
        reply(id, {"content" => JSON::Any.new([text_content(message)]), "isError" => JSON::Any.new(true)})
      else
        reply(id, {"content" => JSON::Any.new([text_content("typed #{arguments["text"].as_s}")]), "isError" => JSON::Any.new(false)})
      end
    else
      reply(id, {} of String => JSON::Any)
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

private FAKE_OP        = File.expand_path("support/fake_op", __DIR__)
private FAKE_OP_LOOKUP = File.expand_path("support/fake_op_lookup", __DIR__)

private def build_proxy(client, upstream, upstream_timeout : Time::Span = 60.seconds)
  vault = PlaywrightSecureMcp::SecretVault.new
  locator = PlaywrightSecureMcp::ItemLocator.new(op_command: FAKE_OP_LOOKUP, account: nil)
  finders = [
    PlaywrightSecureMcp::UrlSecretFinder.new(
      item_locator: locator,
      website_matcher: PlaywrightSecureMcp::WebsiteMatcher.new,
    ),
    PlaywrightSecureMcp::NameSecretFinder.new(locator),
    PlaywrightSecureMcp::TagSecretFinder.new(locator),
  ] of PlaywrightSecureMcp::SecretFinder
  PlaywrightSecureMcp::Proxy.new(
    client: client,
    upstream: upstream,
    secret_resolver: PlaywrightSecureMcp::SecretResolver.new(op_command: FAKE_OP),
    secret_vault: vault,
    redactor: PlaywrightSecureMcp::Redactor.new(vault),
    secret_type_tool: PlaywrightSecureMcp::SecretTypeTool.new,
    secret_guard: PlaywrightSecureMcp::SecretGuard.new(vault),
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
    expect(names.includes?("browser_find_secret_by_url")).to be_true
    expect(names.includes?("browser_find_secret_by_name")).to be_true
    expect(names.includes?("browser_find_secret_by_tag")).to be_true
    w[:client_in_w].close
  end

  it "resolves vault/item/field, types it, and redacts the echoed value" do
    w = wired
    fake = FakeUpstream.new(w[:fake_transport])
    fake.serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"ok","item":"item","field":"field"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(fake.received_browser_type_text).to eq("super-secret-value")
    text = response["result"]["content"].as_a.first["text"].as_s
    expect(text).to eq("typed «REDACTED»")
    w[:client_in_w].close
  end

  it "returns an isError result when op resolution fails" do
    w = wired
    FakeUpstream.new(w[:fake_transport]).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"missing","item":"item","field":"field"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["result"]["isError"].as_bool).to be_true
    w[:client_in_w].close
  end

  it "finds items by the url argument" do
    w = wired
    FakeUpstream.new(w[:fake_transport]).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"browser_find_secret_by_url","arguments":{"url":"https://example.com/login"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["id"].as_i).to eq(12)
    expect(response["result"]["isError"].as_bool).to be_false
    payload = JSON.parse(response["result"]["content"].as_a.first["text"].as_s)
    expect(payload.as_a.first["item"].as_s).to eq("login1")
    w[:client_in_w].close
  end

  it "returns an isError result instead of hanging when a forwarded upstream call never answers" do
    w = wired
    FakeUpstream.new(w[:fake_transport], type_hang: true).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side], upstream_timeout: 200.milliseconds).run }

    call = %({"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"ok","item":"item","field":"field"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["id"].as_i).to eq(14)
    expect(response["result"]["isError"].as_bool).to be_true
    w[:client_in_w].close
  end

  it "finds items by name" do
    w = wired
    FakeUpstream.new(w[:fake_transport]).serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    call = %({"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"browser_find_secret_by_name","arguments":{"item":"Netflix"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    payload = JSON.parse(response["result"]["content"].as_a.first["text"].as_s)
    expect(payload.as_a.first["item"].as_s).to eq("item1")
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
    expect(instructions.includes?("browser_find_secret_by_url")).to be_true
    expect(instructions.includes?("field")).to be_true
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

  it "rejects a browser_type call carrying a known resolved secret" do
    w = wired
    fake = FakeUpstream.new(w[:fake_transport])
    fake.serve
    spawn { build_proxy(w[:client_side], w[:upstream_side]).run }

    secret_call = %({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"ok","item":"item","field":"field"}}})
    w[:driver].write(JSON.parse(secret_call))
    w[:driver].read || raise("no response")

    leak_call = %({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"browser_type","arguments":{"target":"e1","text":"super-secret-value"}}})
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

    call = %({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"browser_type_secret","arguments":{"element":"Password","ref":"e1","vault":"ok","item":"item","field":"field"}}})
    w[:driver].write(JSON.parse(call))
    response = w[:driver].read || raise("no response")

    expect(response["result"]["isError"].as_bool).to be_true
    messages = backend.entries.map(&.message)
    expect(messages.any?(&.includes?("browser_type"))).to be_true
    expect(messages.any?(&.includes?(PlaywrightSecureMcp::Redactor::TOKEN))).to be_true
    expect(messages.none?(&.includes?("super-secret-value"))).to be_true
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
