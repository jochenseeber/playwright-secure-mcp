require "json"

module PlaywrightSecureMcp
  class SecretTypeTool
    class MissingArgumentError < Exception
    end

    NAME          = "browser_type_secret"
    UPSTREAM_TOOL = "browser_type"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_type_secret",
        "description": "Type a secret from 1Password into an element. Provide vault, item (both 1Password IDs, e.g. from browser_find_secret_by_name/_by_tag/_by_url) and field (e.g. \\"username\\" or \\"password\\"). The value is resolved locally and never exposed. Mirrors browser_type otherwise.",
        "annotations": {
          "title": "Type secret into page",
          "readOnlyHint": false,
          "destructiveHint": true,
          "openWorldHint": true
        },
        "inputSchema": {
          "type": "object",
          "properties": {
            "element": { "type": "string", "description": "Human-readable element description used to obtain permission to interact with the element" },
            "ref": { "type": "string", "description": "Exact target element reference from the page snapshot" },
            "vault": { "type": "string", "description": "1Password vault ID" },
            "item": { "type": "string", "description": "1Password item ID" },
            "field": { "type": "string", "description": "Field to type, e.g. username or password" },
            "submit": { "type": "boolean", "description": "Whether to submit entered text (press Enter after)" },
            "slowly": { "type": "boolean", "description": "Whether to type one character at a time" }
          },
          "required": ["element", "ref", "vault", "item", "field"]
        }
      }
      JSON

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def reference(arguments : JSON::Any) : String
      vault = fetch_string(arguments, "vault")
      item = fetch_string(arguments, "item")
      field = fetch_string(arguments, "field")
      "op://#{vault}/#{item}/#{field}"
    end

    def build_browser_type_arguments(*, arguments : JSON::Any, secret : String) : JSON::Any
      built = {} of String => JSON::Any
      built["element"] = required_string(arguments, "element")
      built["target"] = required_string(arguments, "ref")
      built["text"] = JSON::Any.new(secret)
      copy_optional(arguments, built, "submit")
      copy_optional(arguments, built, "slowly")
      JSON::Any.new(built)
    end

    private def required_string(arguments : JSON::Any, key : String) : JSON::Any
      value = arguments[key]?.try(&.as_s?)
      raise MissingArgumentError.new("#{key} is required") if value.nil?
      JSON::Any.new(value)
    end

    private def fetch_string(arguments : JSON::Any, key : String) : String
      value = arguments[key]?.try(&.as_s?)
      raise MissingArgumentError.new("#{key} is required") if value.nil? || value.empty?
      value
    end

    private def copy_optional(arguments : JSON::Any, target : Hash(String, JSON::Any), key : String) : Nil
      value = arguments[key]?
      target[key] = value unless value.nil?
    end
  end
end
