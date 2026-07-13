require "./spec_helper"

{% if flag?(:linux) %}
  Spectator.describe PlaywrightSecureMcp::KeyringCipher do
    it "round-trips a value through a keyring-protected key" do
      cipher =
        begin
          PlaywrightSecureMcp::KeyringCipher.new
        rescue PlaywrightSecureMcp::KeyringCipher::Error
          pending("kernel keyring / AF_ALG unavailable in this environment")
          return
        end
      entry = cipher.encrypt("hunter2".to_slice)
      expect(String.new(cipher.decrypt(entry))).to eq("hunter2")
      expect(cipher.description).to eq("kernel keyring")
    end
  end
{% end %}
