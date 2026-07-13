require "./spec_helper"

private FAKE_OP         = File.expand_path("support/fake_op", __DIR__)
private FAKE_OP_CONTEXT = File.expand_path("support/fake_op_context", __DIR__)
private FAKE_OP_PURPOSE = File.expand_path("support/fake_op_purpose", __DIR__)

Spectator.describe PlaywrightSecureMcp::SecretResolver do
  let(resolver) { PlaywrightSecureMcp::SecretResolver.new(op_command: FAKE_OP) }

  it "resolves a valid reference and trims the trailing newline" do
    expect(resolver.resolve("op://ok/item/field")).to eq("super-secret-value")
  end

  it "rejects a reference without the op:// prefix" do
    expect { resolver.resolve("vault/item/field") }
      .to raise_error(PlaywrightSecureMcp::SecretResolver::InvalidReferenceError)
  end

  it "raises when op exits non-zero" do
    expect { resolver.resolve("op://missing/item/field") }
      .to raise_error(PlaywrightSecureMcp::SecretResolver::ResolutionError)
  end

  it "passes the account to op when no service-account token is set" do
    context_resolver = PlaywrightSecureMcp::SecretResolver.new(op_command: FAKE_OP_CONTEXT, account: "work")
    result = context_resolver.resolve("op://vault/item/field")
    expect(result).to eq("ref=op://vault/item/field account=work token=")
  end

  it "passes the service-account token via the environment and omits the account" do
    context_resolver = PlaywrightSecureMcp::SecretResolver.new(op_command: FAKE_OP_CONTEXT, service_account_token: "ops_tok")
    result = context_resolver.resolve("op://vault/item/field")
    expect(result).to eq("ref=op://vault/item/field account= token=ops_tok")
  end

  context "with an item that has same-labelled fields" do
    let(purpose_resolver) { PlaywrightSecureMcp::SecretResolver.new(op_command: FAKE_OP_PURPOSE) }

    it "resolves username by purpose, ignoring an empty same-labelled field" do
      expect(purpose_resolver.resolve("op://vault/messy/username")).to eq("real-user")
    end

    it "resolves password by purpose" do
      expect(purpose_resolver.resolve("op://vault/messy/password")).to eq("real-pass")
    end

    it "falls back to op read when the item has no matching purpose field" do
      expect(purpose_resolver.resolve("op://vault/plain/username")).to eq("plain-user")
    end

    it "prefers a non-empty field over an empty same-labelled field without a purpose" do
      expect(purpose_resolver.resolve("op://vault/custom/token")).to eq("tok-value")
    end

    it "prefers a field with an id over one without when both are non-empty" do
      expect(purpose_resolver.resolve("op://vault/custom/code")).to eq("with-id-value")
    end
  end
end
