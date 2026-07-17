require "./spec_helper"
require "../src/playwright_secure_mcp/item"

Spectator.describe PlaywrightSecureMcp::Item do
  it "exposes vault and item ids via its key" do
    key = PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "i1")
    item = PlaywrightSecureMcp::Item.new(
      key: key, title: "T", urls: ["https://x"], tags: ["a"],
      fields: {} of String => PlaywrightSecureMcp::Field,
      sections: {} of String => PlaywrightSecureMcp::Section,
    )
    expect(item.vault_id).to eq("v1")
    expect(item.item_id).to eq("i1")
  end

  it "uses value equality for keys (usable as a hash key)" do
    a = PlaywrightSecureMcp::ItemKey.new(vault_id: "v", item_id: "i")
    b = PlaywrightSecureMcp::ItemKey.new(vault_id: "v", item_id: "i")
    cache = {a => 1}
    expect(cache[b]?).to eq(1)
  end
end
