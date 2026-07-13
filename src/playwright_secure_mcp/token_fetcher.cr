require "json"
require "./op_runner"

module PlaywrightSecureMcp
  # Fetches a 1Password service-account token from the `credential` field of
  # the item carrying a given tag. The returned token is a secret: it must
  # never appear in exception messages, logs, or on a command line.
  class TokenFetcher
    class Error < Exception
    end

    def initialize(*, @op_command : String, @account : String?)
    end

    def fetch(tag : String) : String
      credential(item_id(tag))
    end

    private def item_id(tag : String) : String
      items = JSON.parse(run(["item", "list", "--tags", tag, "--format=json"])).as_a
      raise Error.new("no 1Password item tagged #{tag}") if items.empty?

      items[0]["id"].as_s
    end

    private def credential(id : String) : String
      fields = JSON.parse(run(["item", "get", id, "--fields", "label=credential", "--reveal", "--format=json"])).as_a
      field = fields.find { |candidate| candidate["label"]? == "credential" || candidate["id"]? == "credential" }
      raise Error.new("no credential field on 1Password item #{id}") unless field

      field["value"].as_s
    end

    private def run(arguments : Array(String)) : String
      argv = arguments.dup
      if account = @account
        argv << "--account" << account
      end

      output = IO::Memory.new
      status =
        begin
          OpRunner.run(@op_command, argv, output: output)
        rescue error : OpRunner::TimeoutError
          raise Error.new("op #{arguments[0]} #{arguments[1]} timed out: #{error.message}")
        end
      unless status.success?
        raise Error.new("op #{arguments[0]} #{arguments[1]} failed (exit #{status.exit_code? || "signal"})")
      end

      output.to_s
    end
  end
end
