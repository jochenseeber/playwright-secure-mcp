require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::SecretGuard do
  it "does not raise for clean arguments" do
    vault = PlaywrightSecureMcp::SecretVault.new
    guard = PlaywrightSecureMcp::SecretGuard.new(vault)
    arguments = JSON.parse(%({"target":"e1","text":"hello","count":3,"flag":true}))
    expect { guard.check(arguments) }.to_not raise_error
  end

  it "raises when an op:// reference is nested in an array" do
    vault = PlaywrightSecureMcp::SecretVault.new
    guard = PlaywrightSecureMcp::SecretGuard.new(vault)
    arguments = JSON.parse(%({"values":["safe","op://vault/item/field"]}))
    expect { guard.check(arguments) }.to raise_error(PlaywrightSecureMcp::SecretGuard::ViolationError)
  end

  it "raises when an op:// reference is nested in an object" do
    vault = PlaywrightSecureMcp::SecretVault.new
    guard = PlaywrightSecureMcp::SecretGuard.new(vault)
    arguments = JSON.parse(%({"outer":{"inner":"prefix op://vault/item/field suffix"}}))
    expect { guard.check(arguments) }.to raise_error(PlaywrightSecureMcp::SecretGuard::ViolationError)
  end

  it "raises when a string contains a stored vault secret" do
    vault = PlaywrightSecureMcp::SecretVault.new
    vault.store("op://vault/item/field", "super-secret-value")
    guard = PlaywrightSecureMcp::SecretGuard.new(vault)
    arguments = JSON.parse(%({"text":"here is super-secret-value inline"}))
    expect { guard.check(arguments) }.to raise_error(PlaywrightSecureMcp::SecretGuard::ViolationError)
  end
end
