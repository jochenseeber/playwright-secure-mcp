require "json"

module PlaywrightSecureMcp
  # DTO mirroring one entry of `op account list --format=json`.
  struct OpAccount
    include JSON::Serializable
    getter email : String?
    getter account_uuid : String
  end
end
