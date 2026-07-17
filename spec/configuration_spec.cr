require "./spec_helper"
require "../src/playwright_secure_mcp/configuration"
require "../src/playwright_secure_mcp/package_manager"

Spectator.describe PlaywrightSecureMcp::Configuration do
  it "exposes injected values" do
    configuration = PlaywrightSecureMcp::Configuration.new(
      package_manager: PlaywrightSecureMcp::PackageManager::Npm,
      mcp_version: "1.2.3",
      mcp_binary: "mcp-server-playwright",
      command: nil,
      op_command: "op",
      upstream_arguments: ["--headless"],
    )
    expect(configuration.package_manager).to eq(PlaywrightSecureMcp::PackageManager::Npm)
    expect(configuration.mcp_version).to eq("1.2.3")
    expect(configuration.upstream_arguments).to eq(["--headless"])
    expect(configuration.command).to be_nil
    expect(configuration.account).to be_nil
    expect(configuration.account_email).to be_nil
    expect(configuration.account_from_git).to be_nil
    expect(configuration.token_tag).to be_nil
  end

  it "exposes the account and token options" do
    configuration = PlaywrightSecureMcp::Configuration.new(
      package_manager: PlaywrightSecureMcp::PackageManager::Npm,
      mcp_version: "1.2.3",
      mcp_binary: "mcp-server-playwright",
      command: nil,
      op_command: "op",
      upstream_arguments: [] of String,
      account: "work",
      account_email: "mail@example.com",
      account_from_git: "/tmp/repo",
      token_tag: "apikey",
    )
    expect(configuration.account).to eq("work")
    expect(configuration.account_email).to eq("mail@example.com")
    expect(configuration.account_from_git).to eq("/tmp/repo")
    expect(configuration.token_tag).to eq("apikey")
  end
end
