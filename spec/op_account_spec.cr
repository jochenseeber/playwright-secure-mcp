require "./spec_helper"
require "../src/playwright_secure_mcp/op_account"

Spectator.describe PlaywrightSecureMcp::OpAccount do
  it "parses account list entries, tolerating extra keys" do
    accounts = Array(PlaywrightSecureMcp::OpAccount).from_json(
      %([{"email":"a@b.com","account_uuid":"U1","url":"x.1password.com"}]))
    expect(accounts.first.email).to eq("a@b.com")
    expect(accounts.first.account_uuid).to eq("U1")
  end
end
