require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::CommandLineParser do
  let(parser) { PlaywrightSecureMcp::CommandLineParser.new }

  it "applies defaults" do
    configuration = parser.parse([] of String)
    expect(configuration.package_manager).to eq(PlaywrightSecureMcp::PackageManager::Pnpm)
    expect(configuration.mcp_version).to eq("latest")
    expect(configuration.mcp_binary).to eq("mcp-server-playwright")
    expect(configuration.op_command).to eq("op")
  end

  it "parses package manager and version" do
    configuration = parser.parse(["--package-manager", "npm", "--mcp-version", "1.2.3"])
    expect(configuration.package_manager).to eq(PlaywrightSecureMcp::PackageManager::Npm)
    expect(configuration.mcp_version).to eq("1.2.3")
  end

  it "treats --mcp-bin as implying none" do
    configuration = parser.parse(["--mcp-bin", "my-server"])
    expect(configuration.package_manager).to eq(PlaywrightSecureMcp::PackageManager::None)
    expect(configuration.mcp_binary).to eq("my-server")
  end

  it "collects upstream arguments after --" do
    configuration = parser.parse(["--package-manager", "npm", "--", "--headless", "--isolated"])
    expect(configuration.upstream_arguments).to eq(["--headless", "--isolated"])
  end

  it "splits an explicit command override" do
    configuration = parser.parse(["--command", "/usr/bin/env server"])
    expect(configuration.command).to eq(["/usr/bin/env", "server"])
  end

  it "rejects --mcp-bin with an explicit non-none package manager" do
    expect { parser.parse(["--package-manager", "pnpm", "--mcp-bin", "x"]) }
      .to raise_error(PlaywrightSecureMcp::CommandLineParser::Error)
  end

  it "defaults the account and token options to nil" do
    configuration = parser.parse([] of String)
    expect(configuration.account).to be_nil
    expect(configuration.account_email).to be_nil
    expect(configuration.account_from_git).to be_nil
    expect(configuration.token_tag).to be_nil
  end

  it "parses the account options" do
    configuration = parser.parse([
      "--account", "work",
      "--account-email", "mail@example.com",
      "--account-from-git", "/tmp/repo",
    ])
    expect(configuration.account).to eq("work")
    expect(configuration.account_email).to eq("mail@example.com")
    expect(configuration.account_from_git).to eq("/tmp/repo")
  end

  it "parses the token tag" do
    configuration = parser.parse(["--token-tag", "apikey"])
    expect(configuration.token_tag).to eq("apikey")
  end

  it "defaults require_hardware_key to false" do
    configuration = PlaywrightSecureMcp::CommandLineParser.new.parse([] of String)
    expect(configuration.require_hardware_key).to be_false
  end

  it "sets require_hardware_key from --require-hardware-key" do
    configuration = PlaywrightSecureMcp::CommandLineParser.new.parse(["--require-hardware-key"])
    expect(configuration.require_hardware_key).to be_true
  end

  it "rejects an unknown package manager" do
    expect { parser.parse(["--package-manager", "yarn"]) }
      .to raise_error(PlaywrightSecureMcp::CommandLineParser::Error)
  end
end
