require "json"
require "./item"
require "./item_identity"
require "./tool_result"

module PlaywrightSecureMcp
  # Serializes discovery results into an MCP tool result: a JSON array of item
  # identities plus non-secret field metadata. Never includes a field value.
  class ItemResult
    def build(items : Array(Item)) : ToolTextResult
      identities = items.map { |item| identity(item) }
      ToolTextResult.new(identities.to_json, is_error: false)
    end

    private def identity(item : Item) : ItemIdentity
      ItemIdentity.new(
        vault: item.vault_id, item: item.item_id, title: item.title,
        urls: item.urls, tags: item.tags,
        fields: item.fields.values.map { |field| field_meta(field) },
        sections: item.sections.values.map { |section| SectionMeta.new(section.id, section.label) })
    end

    private def field_meta(field : Field) : FieldMeta
      FieldMeta.new(id: field.id, label: field.label, type: field.type,
        purpose: field.purpose, section: field.section_id)
    end
  end
end
