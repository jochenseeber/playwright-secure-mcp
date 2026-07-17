require "./configuration"
require "./package_manager"

module PlaywrightSecureMcp
  class UpstreamCommand
    PACKAGE = "@playwright/mcp"

    def initialize(@configuration : Configuration)
    end

    def tokens : Array(String)
      base = @configuration.command || build_base
      result = base + @configuration.upstream_arguments
      result
    end

    private def build_base : Array(String)
      case @configuration.package_manager
      in PackageManager::Pnpm
        ["pnpm", "dlx", "#{PACKAGE}@#{@configuration.mcp_version}"]
      in PackageManager::Npm
        ["npx", "-y", "#{PACKAGE}@#{@configuration.mcp_version}"]
      in PackageManager::None
        [@configuration.mcp_binary]
      end
    end
  end
end
