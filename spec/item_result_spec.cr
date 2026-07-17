require "./spec_helper"
require "../src/playwright_secure_mcp/encrypted_secret"
require "../src/playwright_secure_mcp/item"
require "../src/playwright_secure_mcp/item_result"

Spectator.describe PlaywrightSecureMcp::ItemResult do
  let(field) do
    PlaywrightSecureMcp::Field.new(
      id: "password", section_id: nil, type: "CONCEALED", purpose: "PASSWORD",
      label: "password",
      value: PlaywrightSecureMcp::EncryptedSecret.new(iv: Bytes.new(0), ciphertext: "cipher".to_slice))
  end

  let(item) do
    PlaywrightSecureMcp::Item.new(
      key: PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "i1"),
      title: "Example", urls: ["https://example.com"], tags: ["work"],
      fields: {"password" => field}, sections: {} of String => PlaywrightSecureMcp::Section)
  end

  it "serializes identity and field metadata but never values" do
    result = PlaywrightSecureMcp::ItemResult.new.build([item])
    text = result.content.first.text
    expect(text.includes?("cipher")).to be_false
    payload = JSON.parse(text).as_a.first
    expect(payload["vault"].as_s).to eq("v1")
    expect(payload["item"].as_s).to eq("i1")
    expect(payload["fields"].as_a.first["label"].as_s).to eq("password")
    expect(payload["fields"].as_a.first["purpose"].as_s).to eq("PASSWORD")
    expect(result.is_error?).to be_false
  end

  it "produces the same wire output as the previous JSON::Any construction" do
    result = PlaywrightSecureMcp::ItemResult.new.build([item])
    expected_payload =
      %([{"vault":"v1","item":"i1","title":"Example","urls":["https://example.com"],) +
        %("tags":["work"],"fields":[{"id":"password","label":"password",) +
        %("type":"CONCEALED","purpose":"PASSWORD"}],"sections":[]}])
    expect(result.content.first.text).to eq(expected_payload)
    expect(result.to_json).to eq(
      %({"content":[{"type":"text","text":#{expected_payload.to_json}}],"isError":false}))
  end

  it "includes sections and a field's section binding" do
    sectioned_field = PlaywrightSecureMcp::Field.new(
      id: "extra", section_id: "sec1", type: "STRING", purpose: nil,
      label: "Extra", value: nil)
    sectioned_item = PlaywrightSecureMcp::Item.new(
      key: PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "i2"),
      title: "Other", urls: [] of String, tags: [] of String,
      fields: {"extra" => sectioned_field},
      sections: {"sec1" => PlaywrightSecureMcp::Section.new(id: "sec1", label: "More")})

    result = PlaywrightSecureMcp::ItemResult.new.build([sectioned_item])
    payload = JSON.parse(result.content.first.text).as_a.first
    expect(payload["fields"].as_a.first["section"].as_s).to eq("sec1")
    expect(payload["fields"].as_a.first["purpose"]?).to be_nil
    expect(payload["sections"].as_a.first["label"].as_s).to eq("More")
  end
end
