require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::Redactor do
  let(vault) { PlaywrightSecureMcp::SecretVault.new }
  let(redactor) { PlaywrightSecureMcp::Redactor.new(vault) }

  it "redacts the raw secret value" do
    vault.store("op://ok/item/field", "s3cr3t&value")
    expect(redactor.redact("token=s3cr3t&value end")).to eq("token=«REDACTED» end")
  end

  it "redacts the URL-encoded form" do
    vault.store("op://ok/item/field", "a b&c")
    encoded = URI.encode_www_form("a b&c")
    expect(redactor.redact("q=#{encoded}")).to eq("q=«REDACTED»")
  end

  it "redacts the Base64 form" do
    vault.store("op://ok/item/field", "hunter2")
    encoded = Base64.strict_encode("hunter2")
    expect(redactor.redact("blob:#{encoded}")).to eq("blob:«REDACTED»")
  end

  it "redacts the HTML-escaped form" do
    vault.store("op://ok/item/field", %(<a>&"))
    escaped = HTML.escape(%(<a>&"))
    expect(redactor.redact("body #{escaped} tail")).to eq("body «REDACTED» tail")
  end

  it "leaves unrelated text untouched" do
    vault.store("op://ok/item/field", "secret")
    expect(redactor.redact("nothing to see")).to eq("nothing to see")
  end
end
