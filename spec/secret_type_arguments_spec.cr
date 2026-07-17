require "./spec_helper"
require "../src/playwright_secure_mcp/secret_type_arguments"

Spectator.describe PlaywrightSecureMcp::SecretTypeArguments do
  it "parses required and optional fields" do
    args = PlaywrightSecureMcp::SecretTypeArguments.from_json(
      %({"element":"E","ref":"e1","vault":"v","item":"i","field":"password","submit":true}))
    expect(args.item).to eq("i")
    expect(args.submit).to be_true
    expect(args.slowly).to be_nil
  end

  it "raises on a missing required field" do
    expect { PlaywrightSecureMcp::SecretTypeArguments.from_json(%({"element":"E"})) }
      .to raise_error(JSON::SerializableError)
  end
end
