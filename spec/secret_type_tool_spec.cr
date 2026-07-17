require "./spec_helper"

private def args(hash) : JSON::Any
  JSON.parse(hash.to_json)
end

Spectator.describe PlaywrightSecureMcp::SecretTypeTool do
  let(tool) { PlaywrightSecureMcp::SecretTypeTool.new }

  it "requires element, ref, vault, item, and field" do
    definition = tool.definition
    expect(definition["name"].as_s).to eq("browser_type_secret")
    required = definition["inputSchema"]["required"].as_a.map(&.as_s)
    expect(required).to eq(["element", "ref", "vault", "item", "field"])
  end

  it "annotates itself as a non-read-only, destructive tool" do
    annotations = tool.definition["annotations"]
    expect(annotations["readOnlyHint"].as_bool).to eq(false)
    expect(annotations["destructiveHint"].as_bool).to eq(true)
  end

  it "builds an ItemKey from vault and item" do
    key = tool.key(args({"vault" => "v1", "item" => "i1", "field" => "password"}))
    expect(key.vault_id).to eq("v1")
    expect(key.item_id).to eq("i1")
  end

  it "extracts the field name" do
    expect(tool.field_name(args({"vault" => "v", "item" => "i", "field" => "password"}))).to eq("password")
  end

  it "builds browser_type arguments with the secret and passes options through" do
    built = tool.build_browser_type_arguments(
      arguments: args({"element" => "Password", "ref" => "e1", "submit" => true}),
      secret: "s3cr3t")
    expect(built["element"].as_s).to eq("Password")
    expect(built["target"].as_s).to eq("e1")
    expect(built["text"].as_s).to eq("s3cr3t")
    expect(built["submit"].as_bool).to be_true
    expect(built.as_h.has_key?("slowly")).to be_false
  end

  it "raises when a required argument is missing" do
    expect { tool.key(args({"item" => "i", "field" => "password"})) }
      .to raise_error(PlaywrightSecureMcp::SecretTypeTool::MissingArgumentError)
  end
end
