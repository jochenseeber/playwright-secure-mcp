require "./spec_helper"
require "../src/playwright_secure_mcp/stdio_transport"

Spectator.describe PlaywrightSecureMcp::StdioTransport do
  it "reads newline-delimited JSON objects and skips blanks" do
    input = IO::Memory.new(%({"a":1}\n\n{"b":2}\n))
    transport = PlaywrightSecureMcp::StdioTransport.new(input: input, output: IO::Memory.new)
    expect(transport.read.try(&.["a"]).try(&.as_i)).to eq(1)
    expect(transport.read.try(&.["b"]).try(&.as_i)).to eq(2)
    expect(transport.read).to be_nil
  end

  it "writes a message as one JSON line" do
    output = IO::Memory.new
    transport = PlaywrightSecureMcp::StdioTransport.new(input: IO::Memory.new, output: output)
    transport.write(JSON.parse(%({"hello":"world"})))
    expect(output.to_s).to eq(%({"hello":"world"}\n))
  end

  it "writes a raw line verbatim plus newline" do
    output = IO::Memory.new
    transport = PlaywrightSecureMcp::StdioTransport.new(input: IO::Memory.new, output: output)
    transport.write_raw(%({"x":"«REDACTED»"}))
    expect(output.to_s).to eq(%({"x":"«REDACTED»"}\n))
  end
end
