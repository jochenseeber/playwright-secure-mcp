require "json"
require "./item"
require "./secret_type_arguments"

module PlaywrightSecureMcp
  class SecretTypeTool
    class MissingArgumentError < Exception
    end

    NAME          = "browser_type_secret"
    UPSTREAM_TOOL = "browser_type"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_type_secret",
        "description": "Type a secret from 1Password into an element. Provide vault, item (both 1Password IDs, e.g. from browser_list_items or browser_find_items_by_name/_by_tag) and field (e.g. \\"username\\" or \\"password\\"). Only allowed while the current page is in the item's URL set. The value is resolved locally and never exposed. Mirrors browser_type otherwise.",
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

    def key(arguments : JSON::Any) : ItemKey
      parsed = parse(arguments)
      ItemKey.new(vault_id: parsed.vault, item_id: parsed.item)
    end

    def field_name(arguments : JSON::Any) : String
      parse(arguments).field
    end

    def build_browser_type_arguments(*, arguments : JSON::Any, secret : String) : JSON::Any
      parsed = parse(arguments)
      built = {
        "element" => JSON::Any.new(parsed.element),
        "target"  => JSON::Any.new(parsed.ref),
        "text"    => JSON::Any.new(secret),
      } of String => JSON::Any
      submit = parsed.submit
      built["submit"] = JSON::Any.new(submit) unless submit.nil?
      slowly = parsed.slowly
      built["slowly"] = JSON::Any.new(slowly) unless slowly.nil?
      JSON::Any.new(built)
    end

    private def parse(arguments : JSON::Any) : SecretTypeArguments
      SecretTypeArguments.from_json(arguments.to_json)
    rescue error : JSON::ParseException | JSON::SerializableError
      raise MissingArgumentError.new("invalid browser_type_secret arguments: #{error.message}")
    end
  end
end
