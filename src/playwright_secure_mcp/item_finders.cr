require "json"
require "./item"
require "./item_cache"
require "./item_locator"
require "./website_matcher"

module PlaywrightSecureMcp
  # A discovery tool that returns the LOGIN items usable on the current browser
  # page, revealing and caching any that are not already cached.
  abstract class ItemFinder
    class MissingArgumentError < Exception
    end

    abstract def name : String
    abstract def definition : JSON::Any
    # Returns the LOGIN items valid for `page_url` matching this tool's criteria,
    # revealing and caching any not already cached.
    abstract def find(page_url : String, arguments : JSON::Any) : Array(Item)

    def initialize(*, @cache : ItemCache, @item_locator : ItemLocator, @website_matcher : WebsiteMatcher)
    end

    # Shared pipeline: filter candidates to the page, reveal uncached, return
    # the surviving items from the cache ordered most-specific-first.
    protected def resolve(page_url : String, candidates : Array(Item)) : Array(Item)
      matching = candidates.select { |candidate| @website_matcher.matches?(page_url, candidate) }
      missing = matching.map(&.key).reject { |key| @cache.has?(key) }
      @item_locator.reveal(missing).each { |item| @cache.store(item) }
      fetched = matching.compact_map { |candidate| @cache.fetch(candidate.key) }
      @website_matcher.rank(page_url, fetched)
    end

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

  class ListItemsFinder < ItemFinder
    NAME = "browser_list_items"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_list_items",
        "description": "List the 1Password LOGIN items usable on the current browser page. Returns item identities and field metadata (no secret values) for use with browser_type_secret. Optionally scope to a vault.",
        "annotations": {"title": "List items for current page", "readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
        "inputSchema": {"type": "object", "properties": {"vault": {"type": "string", "description": "Vault ID or name to scope the search"}}}
      }
      JSON

    def name : String
      NAME
    end

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def find(page_url : String, arguments : JSON::Any) : Array(Item)
      resolve(page_url, @item_locator.list_logins(optional_string(arguments, "vault")))
    end
  end

  class NameItemsFinder < ItemFinder
    NAME = "browser_find_items_by_name"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_find_items_by_name",
        "description": "Find LOGIN items whose title matches, restricted to those usable on the current browser page. Returns item identities and field metadata (no secret values). Optionally scope to a vault.",
        "annotations": {"title": "Find items by name", "readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
        "inputSchema": {"type": "object", "properties": {"item": {"type": "string", "description": "Item title or ID to match"}, "vault": {"type": "string", "description": "Vault ID or name to scope the search"}}, "required": ["item"]}
      }
      JSON

    def name : String
      NAME
    end

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def find(page_url : String, arguments : JSON::Any) : Array(Item)
      needle = required_string(arguments, "item")
      lowered = needle.downcase
      candidates = @item_locator.list_logins(optional_string(arguments, "vault"))
      named = candidates.select { |candidate| candidate.item_id == needle || candidate.title.downcase.includes?(lowered) }
      resolve(page_url, named)
    end
  end

  class TagItemsFinder < ItemFinder
    NAME = "browser_find_items_by_tag"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_find_items_by_tag",
        "description": "Find LOGIN items carrying a tag, restricted to those usable on the current browser page. Returns item identities and field metadata (no secret values). Optionally scope to a vault.",
        "annotations": {"title": "Find items by tag", "readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
        "inputSchema": {"type": "object", "properties": {"tag": {"type": "string", "description": "1Password tag"}, "vault": {"type": "string", "description": "Vault ID or name to scope the search"}}, "required": ["tag"]}
      }
      JSON

    def name : String
      NAME
    end

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def find(page_url : String, arguments : JSON::Any) : Array(Item)
      tag = required_string(arguments, "tag")
      resolve(page_url, @item_locator.list_by_tag(tag, optional_string(arguments, "vault")))
    end
  end
end
