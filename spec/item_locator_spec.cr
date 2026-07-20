require "./spec_helper"
require "../src/playwright_secure_mcp/item"
require "../src/playwright_secure_mcp/item_cache"
require "../src/playwright_secure_mcp/item_locator"

private FAKE_OP_ITEMS = File.expand_path("support/fake_op_items", __DIR__)

Spectator.describe PlaywrightSecureMcp::ItemLocator do
  let(cache) { PlaywrightSecureMcp::ItemCache.new }
  let(locator) do
    PlaywrightSecureMcp::ItemLocator.new(
      op_command: FAKE_OP_ITEMS, account: nil, encryptor: cache)
  end

  it "lists login items as summaries with urls and tags" do
    items = locator.list_logins(nil)
    expect(items.map(&.item_id)).to eq(["login1"])
    expect(items.first.urls).to eq(["https://example.com/login"])
    expect(items.first.tags).to eq(["work"])
    expect(items.first.fields.empty?).to be_true
  end

  it "reveals items in one batched call and encrypts field values" do
    keys = [PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1")]
    items = locator.reveal(keys)
    expect(items.map(&.item_id)).to eq(["login1"]) # non-login dropped
    fields = items.first.fields
    expect(fields.size).to eq(4)
    pw = fields.values.find! { |field| field.purpose == "PASSWORD" }
    value = pw.value
    expect(value).not_to be_nil
    # value is encrypted, not the plaintext
    # ameba:disable Lint/NotNil
    expect(String.new(value.not_nil!.ciphertext)).not_to eq("pw")
  end

  it "caches values only for credential fields, not form artifacts" do
    items = locator.reveal([PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1")])
    fields = items.first.fields
    # username (USERNAME purpose) and password (CONCEALED/PASSWORD) are cached
    expect(fields["username"].value).not_to be_nil
    expect(fields["password"].value).not_to be_nil
    # the plain STRING "Token" field carries no purpose -> metadata only, no value
    expect(fields["custom"].type).to eq("STRING")
    expect(fields["custom"].value).to be_nil
  end

  it "reveals multiple login items from a concatenated op stream" do
    keys = [
      PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1"),
      PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login2"),
    ]
    items = locator.reveal(keys)
    expect(items.map(&.item_id)).to eq(["login1", "login2"])
  end

  it "passes the service token via the environment and omits --account" do
    cache.store_service_token("tok")
    token_locator = PlaywrightSecureMcp::ItemLocator.new(
      op_command: FAKE_OP_ITEMS, account: "acct1", encryptor: cache)
    # The fixture returns the "svc1" login only when OP_SERVICE_ACCOUNT_TOKEN
    # is set and --account is absent, so this asserts the env-token path.
    items = token_locator.list_logins(nil)
    expect(items.map(&.item_id)).to eq(["svc1"])
  end

  it "maps sections onto the item" do
    items = locator.reveal([PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1")])
    expect(items.first.sections["sec1"].label).to eq("More")
    custom = items.first.fields["custom"]
    expect(custom.section_id).to eq("sec1")
  end

  it "does not cache the value of an OTP field" do
    items = locator.reveal([PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1")])
    expect(items.first.fields["otp"].type).to eq(PlaywrightSecureMcp::ItemLocator::OTP_TYPE)
    expect(items.first.fields["otp"].value).to be_nil
  end

  it "fetches the current one-time password live" do
    code = locator.one_time_password(PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1"))
    expect(code).to eq("135790")
  end

  it "raises when op has no one-time password for the item" do
    expect { locator.one_time_password(PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "missing")) }
      .to raise_error(PlaywrightSecureMcp::ItemLocator::Error)
  end
end
