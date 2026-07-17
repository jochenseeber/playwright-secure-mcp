require "json"

module PlaywrightSecureMcp
  # Non-secret field metadata exposed to the client in discovery results.
  # Declaration order is the wire key order; absent purpose/section are omitted.
  struct FieldMeta
    include JSON::Serializable
    getter id : String
    getter label : String
    getter type : String
    @[JSON::Field(emit_null: false)]
    getter purpose : String?
    @[JSON::Field(emit_null: false)]
    getter section : String?

    def initialize(*, @id, @label, @type, @purpose, @section)
    end
  end

  # A section of an item as exposed in discovery results.
  struct SectionMeta
    include JSON::Serializable
    getter id : String
    getter label : String

    def initialize(@id, @label)
    end
  end

  # Identity plus non-secret metadata of a 1Password item, serialized into the
  # discovery result payload. Never carries a field value.
  struct ItemIdentity
    include JSON::Serializable
    getter vault : String
    getter item : String
    getter title : String
    getter urls : Array(String)
    getter tags : Array(String)
    getter fields : Array(FieldMeta)
    getter sections : Array(SectionMeta)

    def initialize(*, @vault, @item, @title, @urls, @tags, @fields, @sections)
    end
  end
end
