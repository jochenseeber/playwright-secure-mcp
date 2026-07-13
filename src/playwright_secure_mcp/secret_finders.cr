require "json"
require "./item"
require "./item_locator"
require "./website_matcher"

module PlaywrightSecureMcp
  # A discovery tool that resolves human identifiers into 1Password item
  # identities from the call arguments alone.
  abstract class SecretFinder
    class MissingArgumentError < Exception
    end

    abstract def name : String
    abstract def definition : JSON::Any
    abstract def find(arguments : JSON::Any) : Array(Item)

    protected def required_string(arguments : JSON::Any, key : String) : String
      value = arguments[key]?.try(&.as_s?)
      raise MissingArgumentError.new("#{key} is required") if value.nil? || value.empty?
      value
    end

    protected def optional_string(arguments : JSON::Any, key : String) : String?
      value = arguments[key]?.try(&.as_s?)
      value.nil? || value.empty? ? nil : value
    end
  end

  class NameSecretFinder < SecretFinder
    NAME = "browser_find_secret_by_name"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_find_secret_by_name",
        "description": "Find a 1Password item by name and return its vault and item IDs for use with browser_type_secret. Optionally scope to a vault.",
        "annotations": {
          "title": "Find secret by name",
          "readOnlyHint": true,
          "destructiveHint": false,
          "openWorldHint": false
        },
        "inputSchema": {
          "type": "object",
          "properties": {
            "item": { "type": "string", "description": "Item ID or name" },
            "vault": { "type": "string", "description": "Vault ID or name to scope the search" }
          },
          "required": ["item"]
        }
      }
      JSON

    def initialize(@item_locator : ItemLocator)
    end

    def name : String
      NAME
    end

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def find(arguments : JSON::Any) : Array(Item)
      item = required_string(arguments, "item")
      vault = optional_string(arguments, "vault")
      [@item_locator.by_name(item, vault)]
    end
  end

  class TagSecretFinder < SecretFinder
    NAME = "browser_find_secret_by_tag"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_find_secret_by_tag",
        "description": "Find 1Password items by tag and return their vault and item IDs for use with browser_type_secret. Optionally scope to a vault.",
        "annotations": {
          "title": "Find secret by tag",
          "readOnlyHint": true,
          "destructiveHint": false,
          "openWorldHint": false
        },
        "inputSchema": {
          "type": "object",
          "properties": {
            "tag": { "type": "string", "description": "1Password tag" },
            "vault": { "type": "string", "description": "Vault ID or name to scope the search" }
          },
          "required": ["tag"]
        }
      }
      JSON

    def initialize(@item_locator : ItemLocator)
    end

    def name : String
      NAME
    end

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def find(arguments : JSON::Any) : Array(Item)
      tag = required_string(arguments, "tag")
      vault = optional_string(arguments, "vault")
      @item_locator.by_tag(tag, vault)
    end
  end

  class UrlSecretFinder < SecretFinder
    NAME = "browser_find_secret_by_url"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_find_secret_by_url",
        "description": "Find 1Password login items matching a web page URL and return their vault and item IDs for use with browser_type_secret. Pass the current page URL as the url argument. Optionally scope to a vault.",
        "annotations": {
          "title": "Find secret by URL",
          "readOnlyHint": true,
          "destructiveHint": false,
          "openWorldHint": false
        },
        "inputSchema": {
          "type": "object",
          "properties": {
            "url": { "type": "string", "description": "The web page URL to match against, e.g. the current page URL" },
            "vault": { "type": "string", "description": "Vault ID or name to scope the search" }
          },
          "required": ["url"]
        }
      }
      JSON

    def initialize(*, @item_locator : ItemLocator, @website_matcher : WebsiteMatcher)
    end

    def name : String
      NAME
    end

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def find(arguments : JSON::Any) : Array(Item)
      url = required_string(arguments, "url")
      vault = optional_string(arguments, "vault")
      @website_matcher.rank(url, @item_locator.logins(vault))
    end
  end
end
