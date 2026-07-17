require "json"
require "./op_account"
require "./op_runner"

module PlaywrightSecureMcp
  # Translates a 1Password account email into the account UUID that
  # `op --account` accepts. `op --account` matches a shorthand, sign-in
  # address, or account/user UUID -- never an email -- so an email obtained
  # from git config or --account-email must be mapped first.
  class AccountLocator
    class Error < Exception
    end

    def initialize(*, @op_command : String)
    end

    # Returns the account unchanged when it is nil or not an email; otherwise
    # looks the email up in `op account list` and returns its account UUID.
    def locate(account : String?) : String?
      return account unless account
      return account unless account.includes?('@')

      accounts = Array(OpAccount).from_json(run)
      match = accounts.find { |candidate| candidate.email == account }
      raise Error.new("no 1Password account for email #{account}") unless match

      match.account_uuid
    rescue error : JSON::ParseException | JSON::SerializableError
      raise Error.new("op account list returned malformed JSON: #{error.message}")
    end

    private def run : String
      output = IO::Memory.new
      status =
        begin
          OpRunner.run(@op_command, ["account", "list", "--format=json"], output: output)
        rescue error : OpRunner::TimeoutError
          raise Error.new("op account list timed out: #{error.message}")
        end
      raise Error.new("op account list failed (exit #{status.exit_code? || "signal"})") unless status.success?

      output.to_s
    end
  end
end
