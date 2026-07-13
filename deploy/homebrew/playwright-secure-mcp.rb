class PlaywrightSecureMcp < Formula
  desc "MCP proxy for the Playwright MCP server that keeps secrets from the LLM"
  homepage "https://github.com/jochenseeber/playwright-secure-mcp"
  version "0.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/jochenseeber/playwright-secure-mcp/releases/download/v#{version}/playwright-secure-mcp-darwin-arm64-system-dynamic"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/jochenseeber/playwright-secure-mcp/releases/download/v#{version}/playwright-secure-mcp-darwin-amd64-system-dynamic"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/jochenseeber/playwright-secure-mcp/releases/download/v#{version}/playwright-secure-mcp-linux-arm64-musl-static"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/jochenseeber/playwright-secure-mcp/releases/download/v#{version}/playwright-secure-mcp-linux-amd64-musl-static"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  # The release asset is a single prebuilt binary (the macOS builds are signed
  # and notarized). Install it under a stable name.
  def install
    bin.install Dir["playwright-secure-mcp-*"].first => "playwright-secure-mcp"
  end

  test do
    assert_match "playwright-secure-mcp", shell_output("#{bin}/playwright-secure-mcp --help")
  end
end
