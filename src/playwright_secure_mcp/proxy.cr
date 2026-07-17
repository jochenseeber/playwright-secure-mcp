require "json"
require "log"
require "random/secure"
require "wait_group"
require "./stdio_transport"
require "./item"
require "./item_cache"
require "./item_locator"
require "./field_selector"
require "./page_url"
require "./website_matcher"
require "./redactor"
require "./secret_type_tool"
require "./secret_guard"
require "./item_finders"
require "./item_result"

module PlaywrightSecureMcp
  class Proxy
    Log = ::Log.for(self)

    # A call to the upstream server (e.g. the injected browser_evaluate) must not
    # block the handler forever if the upstream stalls or never replies. This
    # bounds the wait, mirroring OpRunner's timeout on the op subprocess.
    class UpstreamTimeoutError < Exception
    end

    DEFAULT_UPSTREAM_TIMEOUT = 60.seconds

    # Upstream tool whose invocation also drops the local item cache.
    BROWSER_CLOSE_TOOL = "browser_close"

    INSTRUCTIONS = "This server enforces secure secret handling. " \
                   "Never pass passwords, API keys, tokens, or " \
                   "1Password op:// references as arguments to any " \
                   "tool except browser_type_secret; doing so is a " \
                   "policy violation and will be rejected. To type " \
                   "a secret into a page field, first discover the " \
                   "1Password LOGIN items usable on the current " \
                   "browser page: browser_list_items (all items " \
                   "matching the page), browser_find_items_by_name " \
                   "(by item title), or browser_find_items_by_tag " \
                   "(by tag). These tools return item identities " \
                   "and field metadata, never secret values. Then " \
                   "call browser_type_secret with the vault and " \
                   "item IDs and the field to type (for example " \
                   "\"username\" or \"password\"); the secret value " \
                   "is resolved locally and never exposed, and " \
                   "typing is only allowed while the current page " \
                   "is in the item's URL set. Closing the browser " \
                   "with browser_close also drops the local item " \
                   "cache."

    def initialize(
      *,
      @client : StdioTransport,
      @upstream : StdioTransport,
      @item_cache : ItemCache,
      @item_locator : ItemLocator,
      @field_selector : FieldSelector,
      @page_url : PageUrl,
      @website_matcher : WebsiteMatcher,
      @redactor : Redactor,
      @secret_guard : SecretGuard,
      @secret_type_tool : SecretTypeTool,
      @finders : Array(ItemFinder),
      @item_result : ItemResult,
      @upstream_timeout : Time::Span = DEFAULT_UPSTREAM_TIMEOUT,
    )
      @pending = {} of String => Channel(JSON::Any)
      @mutex = Mutex.new
      @counter = 0
      @id_prefix = "secure-#{Random::Secure.hex(8)}:"
      @handlers = WaitGroup.new
    end

    def run : Nil
      start_upstream_reader
      while message = @client.read
        dispatch_client_message(message)
      end
      @handlers.wait
    end

    # Spawn a handler fiber tracked so `run` can await in-flight replies before exit.
    private def track(&block) : Nil
      @handlers.add(1)
      spawn do
        block.call
      ensure
        @handlers.done
      end
    end

    private def start_upstream_reader : Nil
      spawn do
        while message = @upstream.read
          route_upstream_message(message)
        end
        close_pending_channels
      end
    end

    # On upstream EOF/crash, unblock every waiting handler (receive raises Channel::ClosedError).
    private def close_pending_channels : Nil
      @mutex.synchronize do
        @pending.each_value(&.close)
        @pending.clear
      end
    end

    private def route_upstream_message(message : JSON::Any) : Nil
      id = message["id"]?.try(&.as_s?)
      channel = id ? @mutex.synchronize { @pending[id]? } : nil
      if channel
        channel.send(message)
      else
        send_to_client(message)
      end
    end

    private def dispatch_client_message(message : JSON::Any) : Nil
      method = message["method"]?.try(&.as_s?)
      if method == "initialize" && request?(message)
        track { handle_initialize(message) }
      elsif method == "tools/list" && request?(message)
        track { handle_tools_list(message) }
      elsif method == "tools/call" && request?(message)
        dispatch_tool_call(message)
      else
        @upstream.write(message)
      end
    end

    private def dispatch_tool_call(message : JSON::Any) : Nil
      name = message.dig?("params", "name").try(&.as_s?)
      finder = name ? @finders.find { |candidate| candidate.name == name } : nil
      if name == SecretTypeTool::NAME
        track { handle_secret_call(message) }
      elsif finder
        track { handle_find(finder, message) }
      elsif name == BROWSER_CLOSE_TOOL
        # Closing the browser ends the page session the cached items were
        # discovered for, so drop them before forwarding the real close.
        @item_cache.clear
        forward_tool_call(message)
      else
        forward_tool_call(message)
      end
    end

    private def request?(message : JSON::Any) : Bool
      !message["id"]?.nil?
    end

    private def handle_initialize(message : JSON::Any) : Nil
      params = message["params"]? || JSON::Any.new({} of String => JSON::Any)
      response = call_upstream("initialize", params)
      send_to_client(augment_initialize(response, message["id"]))
    end

    # Reject the call locally when its arguments carry an op:// reference or a
    # resolved secret; otherwise pass it through untouched.
    private def forward_tool_call(message : JSON::Any) : Nil
      arguments = message.dig?("params", "arguments")
      @secret_guard.check(arguments) unless arguments.nil?
      @upstream.write(message)
    rescue error : SecretGuard::ViolationError
      send_to_client(error_result(message["id"], error.message || "secret policy violation"))
    end

    private def handle_tools_list(message : JSON::Any) : Nil
      params = message["params"]? || JSON::Any.new({} of String => JSON::Any)
      response = call_upstream("tools/list", params)
      send_to_client(augment_tools_list(response, message["id"]))
    end

    private def handle_find(finder : ItemFinder, message : JSON::Any) : Nil
      original_id = message["id"]
      arguments = message.dig?("params", "arguments") || JSON::Any.new({} of String => JSON::Any)
      url = current_page_url
      items = finder.find(url, arguments)
      body = {"jsonrpc" => JSON::Any.new("2.0"), "id" => original_id, "result" => @item_result.build(items)}
      send_to_client(JSON::Any.new(body))
    rescue error : ItemLocator::Error | ItemFinder::MissingArgumentError | PageUrl::UnavailableError | UpstreamTimeoutError | KeyError | Channel::ClosedError
      send_to_client(error_result(message["id"], error.message || "item lookup failed"))
    rescue error : Exception
      # An uncaught handler exception would kill this fiber silently and leave
      # the client waiting forever. Always answer the request instead.
      Log.error(exception: error) { "unexpected error handling #{finder.name}" }
      send_to_client(error_result(message["id"], "item lookup failed: #{error.message}"))
    end

    private def handle_secret_call(message : JSON::Any) : Nil
      original_id = message["id"]
      arguments = message["params"]["arguments"]
      key = @secret_type_tool.key(arguments)
      item = fetch_or_reveal(key)
      raise SecretTypeTool::MissingArgumentError.new("no LOGIN item #{key.item_id}") if item.nil?

      url = current_page_url
      unless @website_matcher.matches?(url, item)
        send_to_client(error_result(original_id, "current page #{truncate(url)} is not in this item's URL set"))
        return
      end

      field = @field_selector.select(item, @secret_type_tool.field_name(arguments))
      value = field.value
      raise FieldSelector::NotFoundError.new("field has no value") if value.nil?
      secret = @item_cache.decrypt(value)

      browser_arguments = @secret_type_tool.build_browser_type_arguments(arguments: arguments, secret: secret)
      params = JSON::Any.new({"name" => JSON::Any.new(SecretTypeTool::UPSTREAM_TOOL), "arguments" => browser_arguments})
      response = call_upstream("tools/call", params)
      log_upstream_failure(browser_arguments, response) if upstream_failed?(response)
      send_to_client(with_id(response, original_id))
    rescue error : ItemLocator::Error | FieldSelector::NotFoundError | SecretTypeTool::MissingArgumentError | PageUrl::UnavailableError | UpstreamTimeoutError | KeyError | Channel::ClosedError
      send_to_client(error_result(message["id"], error.message || "secret typing failed"))
    rescue error : Exception
      # An uncaught handler exception would kill this fiber silently and leave
      # the client waiting forever. Always answer the request instead.
      Log.error(exception: error) { "unexpected error handling secret call" }
      send_to_client(error_result(message["id"], "secret typing failed: #{error.message}"))
    end

    private def fetch_or_reveal(key : ItemKey) : Item?
      cached = @item_cache.fetch(key)
      return cached unless cached.nil?
      revealed = @item_locator.reveal([key]).first?
      # Defense-in-depth: accept the revealed item only when it is the one that
      # was asked for, so a specifier resolving elsewhere is treated as a miss.
      return nil if revealed.nil? || revealed.key != key
      @item_cache.store(revealed)
      revealed
    end

    # Defensive: keep a garbage or degenerate page URL from bloating the
    # refusal message sent back to the client.
    MAX_URL_MESSAGE_LENGTH = 200

    private def truncate(url : String) : String
      return url if url.size <= MAX_URL_MESSAGE_LENGTH
      truncated = "#{url[0, MAX_URL_MESSAGE_LENGTH]}…"
      truncated
    end

    private def current_page_url : String
      @page_url.current { |params| call_upstream("tools/call", params) }
    end

    private def upstream_failed?(response : JSON::Any) : Bool
      return true unless response["error"]?.nil?
      response.dig?("result", "isError").try(&.as_bool?) == true
    end

    # Diagnostic only. Both payloads are redacted first so a resolved secret
    # never reaches the log — the same invariant that guards the client.
    private def log_upstream_failure(arguments : JSON::Any, response : JSON::Any) : Nil
      Log.warn do
        "upstream #{SecretTypeTool::UPSTREAM_TOOL} call failed; " \
        "arguments=#{@redactor.redact(arguments.to_json)} " \
        "response=#{@redactor.redact(response.to_json)}"
      end
    end

    private def call_upstream(method : String, params : JSON::Any) : JSON::Any
      id = next_injected_id
      channel = Channel(JSON::Any).new(1)
      @mutex.synchronize { @pending[id] = channel }
      request = JSON::Any.new({
        "jsonrpc" => JSON::Any.new("2.0"),
        "id"      => JSON::Any.new(id),
        "method"  => JSON::Any.new(method),
        "params"  => params,
      })
      @upstream.write(request)
      select
      when response = channel.receive
        @mutex.synchronize { @pending.delete(id) }
        response
      when timeout(@upstream_timeout)
        @mutex.synchronize { @pending.delete(id) }
        raise UpstreamTimeoutError.new(
          "upstream #{method} did not respond within #{@upstream_timeout.total_seconds.to_i}s")
      end
    end

    private def next_injected_id : String
      @mutex.synchronize do
        @counter += 1
        "#{@id_prefix}#{@counter}"
      end
    end

    private def augment_tools_list(response : JSON::Any, id : JSON::Any) : JSON::Any
      body = response.as_h.dup
      body["id"] = id
      # Never fabricate a result next to an error response.
      return JSON::Any.new(body) if body.has_key?("error")
      result = (body["result"]? || JSON::Any.new({} of String => JSON::Any)).as_h.dup
      tools = (result["tools"]? || JSON::Any.new([] of JSON::Any)).as_a.dup
      tools << @secret_type_tool.definition
      @finders.each { |finder| tools << finder.definition }
      result["tools"] = JSON::Any.new(tools)
      body["result"] = JSON::Any.new(result)
      JSON::Any.new(body)
    end

    private def augment_initialize(response : JSON::Any, id : JSON::Any) : JSON::Any
      body = response.as_h.dup
      body["id"] = id
      # Never fabricate a result next to an error response.
      return JSON::Any.new(body) if body.has_key?("error")
      result = (body["result"]? || JSON::Any.new({} of String => JSON::Any)).as_h.dup
      upstream_instructions = result["instructions"]?.try(&.as_s?)
      combined = if upstream_instructions && !upstream_instructions.empty?
                   "#{upstream_instructions}\n\n#{INSTRUCTIONS}"
                 else
                   INSTRUCTIONS
                 end
      result["instructions"] = JSON::Any.new(combined)
      body["result"] = JSON::Any.new(result)
      JSON::Any.new(body)
    end

    private def with_id(response : JSON::Any, id : JSON::Any) : JSON::Any
      body = response.as_h.dup
      body["id"] = id
      JSON::Any.new(body)
    end

    private def error_result(id : JSON::Any, text : String) : JSON::Any
      content = [JSON::Any.new({"type" => JSON::Any.new("text"), "text" => JSON::Any.new(text)})]
      result = {"content" => JSON::Any.new(content), "isError" => JSON::Any.new(true)}
      body = {"jsonrpc" => JSON::Any.new("2.0"), "id" => id, "result" => JSON::Any.new(result)}
      JSON::Any.new(body)
    end

    private def send_to_client(message : JSON::Any) : Nil
      @client.write_raw(@redactor.redact(message.to_json))
    end
  end
end
