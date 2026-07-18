require "./spec_helper"
require "../src/playwright_secure_mcp/item_cache"
require "../src/playwright_secure_mcp/redactor"
require "../src/playwright_secure_mcp/stderr_redactor"

Spectator.describe PlaywrightSecureMcp::StderrRedactor do
  let(cache) do
    c = PlaywrightSecureMcp::ItemCache.new
    c.add_loose_secret("s3cr3t")
    c
  end
  let(redactor) { PlaywrightSecureMcp::Redactor.new(cache) }

  private def drain(io : IO) : Array(String)
    backend = ::Log::MemoryBackend.new
    log = ::Log.new("test", backend, :debug)
    PlaywrightSecureMcp::StderrRedactor.new(io, redactor, log: log).start
    10.times { break unless backend.entries.empty?; Fiber.yield }
    backend.entries.map(&.message)
  end

  it "redacts a cached secret in an upstream stderr line" do
    messages = drain(IO::Memory.new("pw:api browser_type text=s3cr3t\n"))
    expect(messages.any?(&.includes?("«REDACTED»"))).to be_true
    expect(messages.any?(&.includes?("s3cr3t"))).to be_false
  end

  it "bounds an over-long line" do
    messages = drain(IO::Memory.new("x" * 20_000))
    size = messages.first?.try(&.size) || 0
    expect(size > 0).to be_true
    expect(size <= PlaywrightSecureMcp::StderrRedactor::MAX_LINE + 64).to be_true
  end

  it "redacts a secret straddling the read boundary" do
    # "s3cr3t" starts at index 8189, so the first 8192-char read splits it
    # after "s3c"; the reader must reassemble it before emitting.
    io = IO::Memory.new(("x" * 8189) + "s3cr3t" + "\n")
    messages = drain(io)
    joined = messages.join("\n")
    expect(joined.includes?("«REDACTED»")).to be_true
    expect(joined.includes?("s3cr3t")).to be_false
    expect(joined.includes?("s3c")).to be_false # the split head must not leak
  end
end
