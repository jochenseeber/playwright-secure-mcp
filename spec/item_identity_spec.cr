require "./spec_helper"
require "../src/playwright_secure_mcp/item_identity"

Spectator.describe PlaywrightSecureMcp::ItemIdentity do
  it "serializes field metadata with id,label,type and omits absent purpose/section" do
    field = PlaywrightSecureMcp::FieldMeta.new(
      id: "password", label: "password", type: "CONCEALED", purpose: "PASSWORD", section: nil)
    json = field.to_json
    expect(json).to eq(%({"id":"password","label":"password","type":"CONCEALED","purpose":"PASSWORD"}))
  end

  it "serializes field metadata with a section and no purpose" do
    field = PlaywrightSecureMcp::FieldMeta.new(
      id: "extra", label: "Extra", type: "STRING", purpose: nil, section: "sec1")
    expect(field.to_json).to eq(%({"id":"extra","label":"Extra","type":"STRING","section":"sec1"}))
  end

  it "serializes an item identity with keys in wire order" do
    identity = PlaywrightSecureMcp::ItemIdentity.new(
      vault: "v1", item: "i1", title: "Example",
      urls: ["https://example.com"], tags: ["work"],
      fields: [] of PlaywrightSecureMcp::FieldMeta,
      sections: [PlaywrightSecureMcp::SectionMeta.new("sec1", "More")])
    expect(identity.to_json).to eq(
      %({"vault":"v1","item":"i1","title":"Example","urls":["https://example.com"],) +
      %("tags":["work"],"fields":[],"sections":[{"id":"sec1","label":"More"}]}))
  end
end
