require "./spec_helper"
require "../src/playwright_secure_mcp/op_item"

Spectator.describe PlaywrightSecureMcp::OpItem do
  it "parses a full revealed item" do
    json = %({"id":"i1","title":"Example","category":"LOGIN","vault":{"id":"v1"},
      "urls":[{"href":"https://example.com/login"}],"tags":["work"],
      "sections":[{"id":"sec1","label":"More"}],
      "fields":[{"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"pw","section":{"id":"sec1"}}]})
    item = PlaywrightSecureMcp::OpItem.from_json(json)
    expect(item.id).to eq("i1")
    expect(item.vault.id).to eq("v1")
    expect(item.category).to eq("LOGIN")
    expect(item.urls.first.href).to eq("https://example.com/login")
    expect(item.fields.first.value).to eq("pw")
    expect(item.fields.first.section.try(&.id)).to eq("sec1")
  end

  it "tolerates a summary item with no fields/urls" do
    item = PlaywrightSecureMcp::OpItem.from_json(%({"id":"i2","vault":{"id":"v1"}}))
    expect(item.urls.empty?).to be_true
    expect(item.fields.empty?).to be_true
    expect(item.title).to be_nil
  end

  it "parses an array of items" do
    items = Array(PlaywrightSecureMcp::OpItem).from_json(%([{"id":"a","vault":{"id":"v"}},{"id":"b","vault":{"id":"v"}}]))
    expect(items.map(&.id)).to eq(["a", "b"])
  end
end
