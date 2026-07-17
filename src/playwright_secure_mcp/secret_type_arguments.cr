require "json"

module PlaywrightSecureMcp
  # Typed view of the browser_type_secret tool-call arguments. Wire shape only;
  # validation beyond presence/type stays in SecretTypeTool.
  struct SecretTypeArguments
    include JSON::Serializable

    getter element : String
    getter ref : String
    getter vault : String
    getter item : String
    getter field : String
    getter submit : Bool?
    getter slowly : Bool?
  end
end
