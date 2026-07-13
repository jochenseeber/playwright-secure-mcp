require "./spec_helper"

private FAKE_OP_LOOKUP = File.expand_path("support/fake_op_lookup", __DIR__)

Spectator.describe PlaywrightSecureMcp::ItemLocator do
  let(locator) { PlaywrightSecureMcp::ItemLocator.new(op_command: FAKE_OP_LOOKUP, account: nil) }

  it "resolves an item by name to its ids" do
    item = locator.by_name("Netflix", nil)
    expect(item.vault_id).to eq("vault1")
    expect(item.item_id).to eq("item1")
  end

  it "passes the vault scope through to op" do
    item = locator.by_name("Scoped", "privatevault")
    expect(item.item_id).to eq("scoped1")
  end

  it "raises when op fails, naming the full op subcommand" do
    expect { locator.by_name("Scoped", nil) }
      .to raise_error(PlaywrightSecureMcp::ItemLocator::Error, /op item get Scoped --format=json failed/)
  end

  it "lists items by tag" do
    items = locator.by_tag("apikey", nil)
    expect(items.map(&.item_id)).to eq(["item1", "item2"])
  end

  it "raises when op returns a non-array item list" do
    expect { locator.by_tag("badshape", nil) }.to raise_error(PlaywrightSecureMcp::ItemLocator::Error)
  end

  it "forwards the account to op" do
    account_locator = PlaywrightSecureMcp::ItemLocator.new(op_command: FAKE_OP_LOOKUP, account: "acct1")
    item = account_locator.by_name("AccountProbe", nil)
    expect(item.item_id).to eq("acct-item")
  end

  it "passes the service account token via the environment and omits --account" do
    token_locator = PlaywrightSecureMcp::ItemLocator.new(
      op_command: FAKE_OP_LOOKUP,
      account: "acct1",
      service_account_token: "tok"
    )
    item = token_locator.by_name("TokenProbe", nil)
    expect(item.item_id).to eq("tok-item")
  end

  it "fetches login items with their urls" do
    items = locator.logins(nil)
    expect(items.first.urls).to eq(["https://example.com/login"])
  end
end
