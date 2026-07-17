require "file_utils"
require "./spec_helper"
require "../src/playwright_secure_mcp/account_resolver"

Spectator.describe PlaywrightSecureMcp::AccountResolver do
  let(resolver) { PlaywrightSecureMcp::AccountResolver.new }

  def with_git_directory(config : String?, & : String -> Nil) : Nil
    directory = File.join(Dir.tempdir, "account-resolver-spec-#{Random::Secure.hex(8)}")
    Dir.mkdir_p(File.join(directory, ".git"))
    File.write(File.join(directory, ".git", "config"), config) if config
    begin
      yield directory
    ensure
      FileUtils.rm_rf(directory)
    end
  end

  it "prefers the git email over account_email and account" do
    with_git_directory("[user]\n\temail = git@example.com\n") do |directory|
      resolved = resolver.resolve(account: "work", account_email: "mail@example.com", account_from_git: directory)
      expect(resolved).to eq("git@example.com")
    end
  end

  it "prefers account_email over account" do
    resolved = resolver.resolve(account: "work", account_email: "mail@example.com", account_from_git: nil)
    expect(resolved).to eq("mail@example.com")
  end

  it "falls back to account" do
    resolved = resolver.resolve(account: "work", account_email: nil, account_from_git: nil)
    expect(resolved).to eq("work")
  end

  it "returns nil when nothing is given" do
    resolved = resolver.resolve(account: nil, account_email: nil, account_from_git: nil)
    expect(resolved).to be_nil
  end

  it "raises when the git config file does not exist" do
    with_git_directory(nil) do |directory|
      expect { resolver.resolve(account: nil, account_email: nil, account_from_git: directory) }
        .to raise_error(PlaywrightSecureMcp::AccountResolver::Error)
    end
  end

  it "raises when the git config has no user email" do
    with_git_directory("[core]\n\tbare = false\n") do |directory|
      expect { resolver.resolve(account: nil, account_email: nil, account_from_git: directory) }
        .to raise_error(PlaywrightSecureMcp::AccountResolver::Error)
    end
  end
end
