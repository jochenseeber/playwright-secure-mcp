require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::ItemResult do
  let(serializer) { PlaywrightSecureMcp::ItemResult.new }

  it "serializes items as a json identity list in the text content" do
    items = [PlaywrightSecureMcp::Item.new(vault_id: "v1", item_id: "i1", title: "Example", urls: ["https://example.com"])]
    result = serializer.build(items)
    expect(result["isError"].as_bool).to be_false
    payload = JSON.parse(result["content"].as_a.first["text"].as_s)
    expect(payload.as_a.first["vault"].as_s).to eq("v1")
    expect(payload.as_a.first["item"].as_s).to eq("i1")
    expect(payload.as_a.first["url"].as_s).to eq("https://example.com")
    expect(payload.as_a.first["title"].as_s).to eq("Example")
  end

  it "omits url when the item has none" do
    items = [PlaywrightSecureMcp::Item.new(vault_id: "v1", item_id: "i1", title: "T", urls: [] of String)]
    payload = JSON.parse(serializer.build(items)["content"].as_a.first["text"].as_s)
    expect(payload.as_a.first.as_h.has_key?("url")).to be_false
  end
end
