require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::ItemResult do
  it "serializes identity and field metadata but never values" do
    field = PlaywrightSecureMcp::Field.new(
      id: "password", section_id: nil, type: "CONCEALED", purpose: "PASSWORD",
      label: "password",
      value: PlaywrightSecureMcp::EncryptedSecret.new(iv: Bytes.new(0), ciphertext: "cipher".to_slice))
    item = PlaywrightSecureMcp::Item.new(
      key: PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "i1"),
      title: "Example", urls: ["https://example.com"], tags: ["work"],
      fields: {"password" => field}, sections: {} of String => PlaywrightSecureMcp::Section)

    result = PlaywrightSecureMcp::ItemResult.new.build([item])
    text = result["content"].as_a.first["text"].as_s
    expect(text.includes?("cipher")).to be_false
    payload = JSON.parse(text).as_a.first
    expect(payload["vault"].as_s).to eq("v1")
    expect(payload["item"].as_s).to eq("i1")
    expect(payload["fields"].as_a.first["label"].as_s).to eq("password")
    expect(payload["fields"].as_a.first["purpose"].as_s).to eq("PASSWORD")
    expect(result["isError"].as_bool).to be_false
  end
end
