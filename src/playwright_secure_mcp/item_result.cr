require "json"
require "./item"

module PlaywrightSecureMcp
  # Serializes discovery-tool results into an MCP tool result whose text content
  # is a JSON array of item identities. Never includes a secret value.
  class ItemResult
    def build(items : Array(Item)) : JSON::Any
      candidates = items.map { |item| candidate(item) }
      payload = JSON::Any.new(candidates).to_json
      content = [JSON::Any.new({"type" => JSON::Any.new("text"), "text" => JSON::Any.new(payload)})]
      JSON::Any.new({"content" => JSON::Any.new(content), "isError" => JSON::Any.new(false)})
    end

    private def candidate(item : Item) : JSON::Any
      fields = {
        "vault" => JSON::Any.new(item.vault_id),
        "item"  => JSON::Any.new(item.item_id),
        "title" => JSON::Any.new(item.title),
      }
      fields["url"] = JSON::Any.new(item.urls.first) unless item.urls.empty?
      JSON::Any.new(fields)
    end
  end
end
