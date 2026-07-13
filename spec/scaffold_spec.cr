require "./spec_helper"
require "yaml"

Spectator.describe PlaywrightSecureMcp do
  it "exposes the version declared in shard.yml" do
    shard = YAML.parse(File.read(File.expand_path("../shard.yml", __DIR__)))
    expect(PlaywrightSecureMcp::VERSION).to eq(shard["version"].as_s)
  end
end
