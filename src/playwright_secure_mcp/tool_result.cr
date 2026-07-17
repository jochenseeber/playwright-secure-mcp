require "json"

module PlaywrightSecureMcp
  # One entry of an MCP tool result's `content` array; always text here.
  struct ToolContent
    include JSON::Serializable
    getter type : String = "text"
    getter text : String

    def initialize(@text : String)
    end
  end

  # An MCP tool result carrying a single text content entry:
  # {"content":[{"type":"text","text":...}],"isError":bool}.
  struct ToolTextResult
    include JSON::Serializable
    getter content : Array(ToolContent)
    @[JSON::Field(key: "isError")]
    getter? is_error : Bool

    def initialize(text : String, *, is_error : Bool)
      @content = [ToolContent.new(text)]
      @is_error = is_error
    end
  end

  # A complete JSON-RPC response wrapping a tool result for the client.
  struct JsonRpcToolResult
    include JSON::Serializable
    getter jsonrpc : String = "2.0"
    getter id : JSON::Any
    getter result : ToolTextResult

    def initialize(@id : JSON::Any, @result : ToolTextResult)
    end
  end
end
