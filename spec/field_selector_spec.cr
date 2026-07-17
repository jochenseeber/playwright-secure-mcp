require "./spec_helper"

private def fld(id, purpose, label, has_value)
  PlaywrightSecureMcp::Field.new(
    id: id, section_id: nil, type: "STRING", purpose: purpose, label: label,
    value: has_value ? PlaywrightSecureMcp::EncryptedSecret.new(iv: Bytes.new(0), ciphertext: Bytes.new(1)) : nil)
end

private def item_with(fields)
  PlaywrightSecureMcp::Item.new(
    key: PlaywrightSecureMcp::ItemKey.new(vault_id: "v", item_id: "i"),
    title: "t", urls: [] of String, tags: [] of String,
    fields: fields, sections: {} of String => PlaywrightSecureMcp::Section)
end

Spectator.describe PlaywrightSecureMcp::FieldSelector do
  let(selector) { PlaywrightSecureMcp::FieldSelector.new }

  it "selects by purpose for username/password" do
    item = item_with({
      "f1" => fld("f1", "PASSWORD", "Kennwort", true),
      "f2" => fld("f2", nil, "password", false),
    })
    expect(selector.select(item, "password").id).to eq("f1")
  end

  it "falls back to label then id" do
    item = item_with({"f1" => fld("f1", nil, "API Key", true)})
    expect(selector.select(item, "API Key").id).to eq("f1")
    expect(selector.select(item, "f1").id).to eq("f1")
  end

  it "raises when no field matches" do
    item = item_with({"f1" => fld("f1", nil, "x", true)})
    expect { selector.select(item, "nope") }.to raise_error(PlaywrightSecureMcp::FieldSelector::NotFoundError)
  end
end
