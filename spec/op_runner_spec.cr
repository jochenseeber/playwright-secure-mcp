require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::OpRunner do
  it "returns the captured output and a successful status" do
    output = IO::Memory.new
    status = PlaywrightSecureMcp::OpRunner.run("/bin/sh", ["-c", "printf hello"], output: output)
    expect(status.success?).to be_true
    expect(output.to_s).to eq("hello")
  end

  it "reports a non-zero exit without raising" do
    status = PlaywrightSecureMcp::OpRunner.run("/bin/sh", ["-c", "exit 3"])
    expect(status.success?).to be_false
  end

  it "feeds stdin to the command" do
    output = IO::Memory.new
    status = PlaywrightSecureMcp::OpRunner.run(
      "/bin/sh", ["-c", "cat"], input: IO::Memory.new("piped"), output: output)
    expect(status.success?).to be_true
    expect(output.to_s).to eq("piped")
  end

  it "raises TimeoutError and kills a command that exceeds the timeout" do
    elapsed = Time.measure do
      expect do
        PlaywrightSecureMcp::OpRunner.run("/bin/sh", ["-c", "sleep 30"], timeout: 0.3.seconds)
      end.to raise_error(PlaywrightSecureMcp::OpRunner::TimeoutError)
    end
    # It returns promptly at the timeout rather than waiting out the sleep.
    expect(elapsed < 5.seconds).to be_true
  end
end
