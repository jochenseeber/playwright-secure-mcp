require "./encrypted_secret"

module PlaywrightSecureMcp
  # Identity of a cached 1Password item: the {vault, item} pair. A record, so it
  # has value equality and hashing and can key the cache.
  record ItemKey, vault_id : String, item_id : String

  # A section of a 1Password item (groups custom fields).
  record Section, id : String, label : String

  # A single field of a 1Password item. Only `value` is a secret; it is stored
  # encrypted, and is nil for fields that have no value.
  record Field,
    id : String,
    section_id : String?,
    type : String,
    purpose : String?,
    label : String,
    value : EncryptedSecret?

  # A cached 1Password LOGIN item. Carries only non-secret metadata in the clear;
  # each field's secret value is encrypted inside `Field#value`.
  record Item,
    key : ItemKey,
    title : String,
    urls : Array(String),
    tags : Array(String),
    fields : Hash(String, Field),
    sections : Hash(String, Section) do
    def vault_id : String
      key.vault_id
    end

    def item_id : String
      key.item_id
    end
  end
end
