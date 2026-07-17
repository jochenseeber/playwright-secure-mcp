require "./spec_helper"
require "../src/playwright_secure_mcp/account_locator"

private FAKE_OP_ACCOUNTS = File.expand_path("support/fake_op_accounts", __DIR__)

Spectator.describe PlaywrightSecureMcp::AccountLocator do
  let(locator) { PlaywrightSecureMcp::AccountLocator.new(op_command: FAKE_OP_ACCOUNTS) }

  it "returns the account uuid for a known email" do
    expect(locator.locate("git@example.com")).to eq("AAAA1111")
  end

  it "passes a non-email value through unchanged" do
    expect(locator.locate("work")).to eq("work")
  end

  it "passes nil through unchanged" do
    expect(locator.locate(nil)).to be_nil
  end

  it "raises for an unknown email" do
    expect { locator.locate("missing@example.com") }
      .to raise_error(PlaywrightSecureMcp::AccountLocator::Error)
  end
end
