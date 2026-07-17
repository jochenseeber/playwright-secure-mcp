require "./spec_helper"
require "../src/playwright_secure_mcp/tpm_cipher"

{% if flag?(:linux) %}
  Spectator.describe PlaywrightSecureMcp::TpmCipher do
    it "round-trips a value through a TPM-sealed key" do
      unless File.exists?("/dev/tpmrm0")
        pending("no /dev/tpmrm0 device in this environment")
        return
      end
      cipher =
        begin
          PlaywrightSecureMcp::TpmCipher.new
        rescue PlaywrightSecureMcp::TpmCipher::Error
          pending("TPM unavailable in this environment")
          return
        end
      entry = cipher.encrypt("hunter2".to_slice)
      expect(String.new(cipher.decrypt(entry))).to eq("hunter2")
      expect(cipher.description).to eq("TPM 2.0")
    end
  end
{% end %}
