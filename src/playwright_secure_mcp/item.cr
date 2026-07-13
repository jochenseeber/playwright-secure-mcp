module PlaywrightSecureMcp
  # Identity of a 1Password item as surfaced by the discovery tools. Carries
  # only non-secret identifiers -- never a field value.
  record Item,
    vault_id : String,
    item_id : String,
    title : String,
    urls : Array(String) = [] of String
end
