require "./spec_helper"

private FAKE_OP_ITEMS = File.expand_path("support/fake_op_items", __DIR__)

Spectator.describe PlaywrightSecureMcp::TokenFetcher do
  let(fetcher) { PlaywrightSecureMcp::TokenFetcher.new(op_command: FAKE_OP_ITEMS, account: nil) }

  it "fetches the credential of the item tagged with the given tag" do
    expect(fetcher.fetch("apikey")).to eq("ops_service_token")
  end

  it "raises when no item carries the tag" do
    expect { fetcher.fetch("unknown-tag") }
      .to raise_error(PlaywrightSecureMcp::TokenFetcher::Error)
  end
end
