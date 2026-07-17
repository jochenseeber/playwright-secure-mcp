require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::SecretGuard do
  it "does not raise for clean arguments" do
    cache = PlaywrightSecureMcp::ItemCache.new
    guard = PlaywrightSecureMcp::SecretGuard.new(cache)
    arguments = JSON.parse(%({"target":"e1","text":"hello","count":3,"flag":true}))
    expect { guard.check(arguments) }.to_not raise_error
  end

  it "raises when an op:// reference is nested in an array" do
    cache = PlaywrightSecureMcp::ItemCache.new
    guard = PlaywrightSecureMcp::SecretGuard.new(cache)
    arguments = JSON.parse(%({"values":["safe","op://vault/item/field"]}))
    expect { guard.check(arguments) }.to raise_error(PlaywrightSecureMcp::SecretGuard::ViolationError)
  end

  it "raises when an op:// reference is nested in an object" do
    cache = PlaywrightSecureMcp::ItemCache.new
    guard = PlaywrightSecureMcp::SecretGuard.new(cache)
    arguments = JSON.parse(%({"outer":{"inner":"prefix op://vault/item/field suffix"}}))
    expect { guard.check(arguments) }.to raise_error(PlaywrightSecureMcp::SecretGuard::ViolationError)
  end

  it "raises when a string contains a cached secret" do
    cache = PlaywrightSecureMcp::ItemCache.new
    cache.add_loose_secret("super-secret-value")
    guard = PlaywrightSecureMcp::SecretGuard.new(cache)
    arguments = JSON.parse(%({"text":"here is super-secret-value inline"}))
    expect { guard.check(arguments) }.to raise_error(PlaywrightSecureMcp::SecretGuard::ViolationError)
  end
end
