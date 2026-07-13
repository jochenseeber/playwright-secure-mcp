require "./package_manager"

module PlaywrightSecureMcp
  class Configuration
    getter package_manager : PackageManager
    getter mcp_version : String
    getter mcp_binary : String
    getter command : Array(String)?
    getter op_command : String
    getter upstream_arguments : Array(String)
    getter account : String?
    getter account_email : String?
    getter account_from_git : String?
    getter token_tag : String?
    # ameba:disable Naming/QueryBoolMethods
    getter require_hardware_key : Bool

    def initialize(
      *,
      @package_manager : PackageManager,
      @mcp_version : String,
      @mcp_binary : String,
      @command : Array(String)?,
      @op_command : String,
      @upstream_arguments : Array(String),
      @account : String? = nil,
      @account_email : String? = nil,
      @account_from_git : String? = nil,
      @token_tag : String? = nil,
      @require_hardware_key : Bool = false,
    )
    end
  end
end
