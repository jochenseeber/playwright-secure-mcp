require "./spec_helper"
require "../src/playwright_secure_mcp/cipher_selector"
require "../src/playwright_secure_mcp/in_memory_cipher"
require "../src/playwright_secure_mcp/secret_cipher"

private def mem : PlaywrightSecureMcp::SecretCipher
  PlaywrightSecureMcp::InMemoryCipher.new
end

private def candidate(name, hardware, &build : -> PlaywrightSecureMcp::SecretCipher)
  PlaywrightSecureMcp::CipherCandidate.new(name: name, hardware: hardware, build: build)
end

Spectator.describe PlaywrightSecureMcp::CipherSelector do
  let(log) { ::Log.for("test") }

  it "selects the first available candidate" do
    hw = mem
    selector = PlaywrightSecureMcp::CipherSelector.new(
      [candidate("hw", true) { hw }, candidate("soft", false) { mem }], log: log)
    expect(selector.select(require_hardware: false)).to be(hw)
  end

  it "falls through when a higher tier fails to build" do
    soft = mem
    selector = PlaywrightSecureMcp::CipherSelector.new([
      candidate("hw", true) { raise "no enclave" },
      candidate("soft", false) { soft },
    ], log: log)
    expect(selector.select(require_hardware: false)).to be(soft)
  end

  it "raises under strict mode when no hardware tier is available" do
    selector = PlaywrightSecureMcp::CipherSelector.new([
      candidate("hw", true) { raise "no enclave" },
      candidate("soft", false) { mem },
    ], log: log)
    expect { selector.select(require_hardware: true) }
      .to raise_error(PlaywrightSecureMcp::CipherSelector::Error)
  end

  it "skips non-hardware candidates under strict mode and uses hardware" do
    hw = mem
    selector = PlaywrightSecureMcp::CipherSelector.new([
      candidate("soft", false) { mem },
      candidate("hw", true) { hw },
    ], log: log)
    expect(selector.select(require_hardware: true)).to be(hw)
  end
end
