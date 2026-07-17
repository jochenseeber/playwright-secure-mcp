require "json"
require "./item"
require "./item_cache"
require "./item_locator"
require "./website_matcher"

module PlaywrightSecureMcp
  # Typed views of the finder tool-call arguments. Wire shape only; empty-string
  # normalization stays in the finders.
  private struct NameArgs
    include JSON::Serializable
    getter item : String
    getter vault : String?
  end

  private struct TagArgs
    include JSON::Serializable
    getter tag : String
    getter vault : String?
  end

  private struct ScopeArgs
    include JSON::Serializable
    getter vault : String?
  end

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

    # An absent or empty vault argument means "search all vaults".
    protected def scoped_vault(vault : String?) : String?
      vault.nil? || vault.empty? ? nil : vault
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
      parsed = parse(arguments)
      resolve(page_url, @item_locator.list_logins(scoped_vault(parsed.vault)))
    end

    private def parse(arguments : JSON::Any) : ScopeArgs
      ScopeArgs.from_json(arguments.to_json)
    rescue error : JSON::ParseException | JSON::SerializableError
      raise MissingArgumentError.new("invalid #{NAME} arguments: #{error.message}")
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
      parsed = parse(arguments)
      needle = parsed.item
      raise MissingArgumentError.new("item is required") if needle.empty?
      lowered = needle.downcase
      candidates = @item_locator.list_logins(scoped_vault(parsed.vault))
      named = candidates.select { |candidate| candidate.item_id == needle || candidate.title.downcase.includes?(lowered) }
      resolve(page_url, named)
    end

    private def parse(arguments : JSON::Any) : NameArgs
      NameArgs.from_json(arguments.to_json)
    rescue error : JSON::ParseException | JSON::SerializableError
      raise MissingArgumentError.new("invalid #{NAME} arguments: #{error.message}")
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
      parsed = parse(arguments)
      tag = parsed.tag
      raise MissingArgumentError.new("tag is required") if tag.empty?
      resolve(page_url, @item_locator.list_by_tag(tag, scoped_vault(parsed.vault)))
    end

    private def parse(arguments : JSON::Any) : TagArgs
      TagArgs.from_json(arguments.to_json)
    rescue error : JSON::ParseException | JSON::SerializableError
      raise MissingArgumentError.new("invalid #{NAME} arguments: #{error.message}")
    end
  end
end
