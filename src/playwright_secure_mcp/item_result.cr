require "json"
require "./item"

module PlaywrightSecureMcp
  # Serializes discovery results into an MCP tool result: a JSON array of item
  # identities plus non-secret field metadata. Never includes a field value.
  class ItemResult
    def build(items : Array(Item)) : JSON::Any
      payload = JSON::Any.new(items.map { |item| candidate(item) }).to_json
      content = [JSON::Any.new({"type" => JSON::Any.new("text"), "text" => JSON::Any.new(payload)})]
      JSON::Any.new({"content" => JSON::Any.new(content), "isError" => JSON::Any.new(false)})
    end

    private def candidate(item : Item) : JSON::Any
      JSON::Any.new({
        "vault"    => JSON::Any.new(item.vault_id),
        "item"     => JSON::Any.new(item.item_id),
        "title"    => JSON::Any.new(item.title),
        "urls"     => JSON::Any.new(item.urls.map { |url| JSON::Any.new(url) }),
        "tags"     => JSON::Any.new(item.tags.map { |tag| JSON::Any.new(tag) }),
        "fields"   => JSON::Any.new(item.fields.values.map { |field| field(field) }),
        "sections" => JSON::Any.new(item.sections.values.map { |section| section(section) }),
      })
    end

    private def field(field : Field) : JSON::Any
      entry = {
        "id"    => JSON::Any.new(field.id),
        "label" => JSON::Any.new(field.label),
        "type"  => JSON::Any.new(field.type),
      } of String => JSON::Any
      purpose = field.purpose
      entry["purpose"] = JSON::Any.new(purpose) unless purpose.nil?
      section_id = field.section_id
      entry["section"] = JSON::Any.new(section_id) unless section_id.nil?
      JSON::Any.new(entry)
    end

    private def section(section : Section) : JSON::Any
      JSON::Any.new({"id" => JSON::Any.new(section.id), "label" => JSON::Any.new(section.label)})
    end
  end
end
