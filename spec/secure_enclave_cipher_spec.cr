require "./spec_helper"
require "../src/playwright_secure_mcp/secure_enclave_cipher"

{% if flag?(:darwin) %}
  Spectator.describe PlaywrightSecureMcp::SecureEnclaveCipher do
    it "round-trips a value through an enclave-protected key" do
      cipher =
        begin
          PlaywrightSecureMcp::SecureEnclaveCipher.new
        rescue PlaywrightSecureMcp::SecureEnclaveCipher::Error
          pending("Secure Enclave unavailable in this environment")
          return
        end
      entry = cipher.encrypt("hunter2".to_slice)
      expect(String.new(cipher.decrypt(entry))).to eq("hunter2")
      expect(cipher.description).to eq("Secure Enclave")
    end
  end
{% end %}
