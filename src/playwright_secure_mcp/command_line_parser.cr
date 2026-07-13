require "option_parser"
require "./configuration"
require "./package_manager"

module PlaywrightSecureMcp
  class CommandLineParser
    class Error < Exception
    end

    def parse(arguments : Array(String)) : Configuration
      package_manager_option = nil.as(String?)
      mcp_version = "latest"
      mcp_binary_option = nil.as(String?)
      command_option = nil.as(String?)
      op_command = "op"
      account = nil.as(String?)
      account_email = nil.as(String?)
      account_from_git = nil.as(String?)
      token_tag = nil.as(String?)
      require_hardware_key = false
      upstream_arguments = [] of String

      option_parser = OptionParser.new
      option_parser.banner = "Usage: playwright-secure-mcp [options] [-- upstream args]"
      option_parser.on("--package-manager NAME", "pnpm (default), npm, or none") { |value| package_manager_option = value }
      option_parser.on("--mcp-version VERSION", "@playwright/mcp version (default: latest)") { |value| mcp_version = value }
      option_parser.on("--mcp-bin BINARY", "pre-installed binary; implies --package-manager none") { |value| mcp_binary_option = value }
      option_parser.on("--command LINE", "explicit upstream command override") { |value| command_option = value }
      option_parser.on("--op-command PATH", "1Password CLI binary (default: op)") { |value| op_command = value }
      option_parser.on("--account ACCOUNT", "1Password account (shorthand, email, or ID)") { |value| account = value }
      option_parser.on("--account-email EMAIL", "1Password account email") { |value| account_email = value }
      option_parser.on("--account-from-git DIR", "read account email from DIR/.git/config") { |value| account_from_git = value }
      option_parser.on("--token-tag TAG", "1Password item tag holding a service-account token") { |value| token_tag = value }
      option_parser.on("--require-hardware-key", "refuse to start without Secure Enclave/TPM key protection") { require_hardware_key = true }
      option_parser.on("-h", "--help", "show help") { puts option_parser; exit(0) }
      option_parser.invalid_option { |flag| raise Error.new("unknown option: #{flag}") }
      option_parser.unknown_args { |_, after_double_dash| upstream_arguments = after_double_dash }
      option_parser.parse(arguments)

      configuration = build_configuration(
        package_manager_option: package_manager_option,
        mcp_version: mcp_version,
        mcp_binary_option: mcp_binary_option,
        command_option: command_option,
        op_command: op_command,
        account: account,
        account_email: account_email,
        account_from_git: account_from_git,
        token_tag: token_tag,
        require_hardware_key: require_hardware_key,
        upstream_arguments: upstream_arguments,
      )
      configuration
    end

    private def build_configuration(
      *,
      package_manager_option : String?,
      mcp_version : String,
      mcp_binary_option : String?,
      command_option : String?,
      op_command : String,
      account : String?,
      account_email : String?,
      account_from_git : String?,
      token_tag : String?,
      require_hardware_key : Bool,
      upstream_arguments : Array(String),
    ) : Configuration
      explicit_package_manager = resolve_package_manager(package_manager_option)

      if mcp_binary_option && explicit_package_manager && explicit_package_manager != PackageManager::None
        raise Error.new("--mcp-bin cannot be combined with --package-manager #{package_manager_option}")
      end

      package_manager =
        if mcp_binary_option
          PackageManager::None
        else
          explicit_package_manager || PackageManager::Pnpm
        end

      configuration = Configuration.new(
        package_manager: package_manager,
        mcp_version: mcp_version,
        mcp_binary: mcp_binary_option || "mcp-server-playwright",
        command: command_option.try(&.split(' ', remove_empty: true)),
        op_command: op_command,
        account: account,
        account_email: account_email,
        account_from_git: account_from_git,
        token_tag: token_tag,
        require_hardware_key: require_hardware_key,
        upstream_arguments: upstream_arguments,
      )
      configuration
    end

    private def resolve_package_manager(name : String?) : PackageManager?
      return nil if name.nil?
      parsed = PackageManager.parse?(name)
      raise Error.new("unknown package manager: #{name}") if parsed.nil?
      parsed
    end
  end
end
