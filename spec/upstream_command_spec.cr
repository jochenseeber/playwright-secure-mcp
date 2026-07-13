require "./spec_helper"

private def configuration(
  *,
  package_manager = PlaywrightSecureMcp::PackageManager::Pnpm,
  mcp_version = "latest",
  mcp_binary = "mcp-server-playwright",
  command : Array(String)? = nil,
  upstream_arguments = [] of String,
)
  PlaywrightSecureMcp::Configuration.new(
    package_manager: package_manager,
    mcp_version: mcp_version,
    mcp_binary: mcp_binary,
    command: command,
    op_command: "op",
    upstream_arguments: upstream_arguments,
  )
end

Spectator.describe PlaywrightSecureMcp::UpstreamCommand do
  it "builds a pnpm dlx command" do
    tokens = PlaywrightSecureMcp::UpstreamCommand.new(configuration(mcp_version: "1.2.3")).tokens
    expect(tokens).to eq(["pnpm", "dlx", "@playwright/mcp@1.2.3"])
  end

  it "builds an npx command" do
    tokens = PlaywrightSecureMcp::UpstreamCommand.new(
      configuration(package_manager: PlaywrightSecureMcp::PackageManager::Npm)
    ).tokens
    expect(tokens).to eq(["npx", "-y", "@playwright/mcp@latest"])
  end

  it "uses the pre-installed binary for none" do
    tokens = PlaywrightSecureMcp::UpstreamCommand.new(
      configuration(package_manager: PlaywrightSecureMcp::PackageManager::None, mcp_binary: "my-playwright")
    ).tokens
    expect(tokens).to eq(["my-playwright"])
  end

  it "prefers an explicit command override" do
    tokens = PlaywrightSecureMcp::UpstreamCommand.new(
      configuration(command: ["/usr/bin/env", "server"])
    ).tokens
    expect(tokens).to eq(["/usr/bin/env", "server"])
  end

  it "appends upstream arguments in every mode" do
    tokens = PlaywrightSecureMcp::UpstreamCommand.new(
      configuration(upstream_arguments: ["--headless", "--isolated"])
    ).tokens
    expect(tokens).to eq(["pnpm", "dlx", "@playwright/mcp@latest", "--headless", "--isolated"])
  end
end
