require "./spec_helper"
require "../src/playwright_secure_mcp/package_manager"

Spectator.describe PlaywrightSecureMcp::PackageManager do
  it "parses known names case-insensitively" do
    expect(PlaywrightSecureMcp::PackageManager.parse?("pnpm")).to eq(PlaywrightSecureMcp::PackageManager::Pnpm)
    expect(PlaywrightSecureMcp::PackageManager.parse?("NPM")).to eq(PlaywrightSecureMcp::PackageManager::Npm)
    expect(PlaywrightSecureMcp::PackageManager.parse?("none")).to eq(PlaywrightSecureMcp::PackageManager::None)
  end

  it "returns nil for unknown names" do
    expect(PlaywrightSecureMcp::PackageManager.parse?("yarn")).to be_nil
  end
end
