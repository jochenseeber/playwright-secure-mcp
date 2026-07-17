require "json"

module PlaywrightSecureMcp
  # DTOs mirroring `op ... --format=json` item output. Wire shape only; mapping
  # to the domain `Item` (encryption, credential-filtering, hash-keying) lives
  # in ItemLocator.
  struct OpVault
    include JSON::Serializable
    getter id : String
  end

  struct OpUrl
    include JSON::Serializable
    getter href : String?
  end

  struct OpFieldSection
    include JSON::Serializable
    getter id : String?
  end

  struct OpField
    include JSON::Serializable
    getter id : String?
    getter label : String?
    getter type : String?
    getter purpose : String?
    getter value : String?
    getter section : OpFieldSection?
  end

  struct OpSection
    include JSON::Serializable
    getter id : String?
    getter label : String?
  end

  struct OpItem
    include JSON::Serializable
    getter id : String
    getter title : String?
    getter category : String?
    getter vault : OpVault
    getter urls : Array(OpUrl) = [] of OpUrl
    getter tags : Array(String) = [] of String
    getter fields : Array(OpField) = [] of OpField
    getter sections : Array(OpSection) = [] of OpSection
  end
end
