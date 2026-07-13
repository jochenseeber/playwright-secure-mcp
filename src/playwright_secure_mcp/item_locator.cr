require "json"
require "./item"
require "./op_runner"

module PlaywrightSecureMcp
  # Looks up 1Password items via the `op` CLI. Returns only identities; never
  # runs with --reveal, so no secret value is fetched here.
  class ItemLocator
    class Error < Exception
    end

    def initialize(*, @op_command : String, @account : String?, @service_account_token : String? = nil)
    end

    def by_name(item : String, vault : String?) : Item
      output = run(["item", "get", item, "--format=json"], vault)
      item_from(JSON.parse(output))
    end

    def by_tag(tag : String, vault : String?) : Array(Item)
      output = run(["item", "list", "--tags", tag, "--format=json"], vault)
      items_from(JSON.parse(output))
    end

    def logins(vault : String?) : Array(Item)
      # `op item list` already includes each item's urls, so no per-item fetch
      # is needed. The `urls` key is simply omitted for items that have none,
      # which `item_from` tolerates.
      listed = run(["item", "list", "--categories", "Login", "--format=json"], vault)
      items_from(JSON.parse(listed))
    end

    private def items_from(parsed : JSON::Any) : Array(Item)
      parsed.as_a.map { |entry| item_from(entry) }
    rescue error : TypeCastError
      raise Error.new("op returned a malformed item list: #{error.message}")
    end

    private def item_from(entry : JSON::Any) : Item
      vault_id = entry["vault"]["id"].as_s
      item_id = entry["id"].as_s
      title = entry["title"]?.try(&.as_s) || ""
      urls = entry["urls"]?.try(&.as_a.compact_map(&.["href"]?.try(&.as_s))) || [] of String
      Item.new(vault_id: vault_id, item_id: item_id, title: title, urls: urls)
    rescue error : KeyError | TypeCastError | NilAssertionError
      raise Error.new("op returned a malformed item: #{error.message}")
    end

    private def run(arguments : Array(String), vault : String?, *, input : String? = nil) : String
      argv = arguments.dup
      argv << "--vault" << vault if vault
      if token = @service_account_token
        env = {"OP_SERVICE_ACCOUNT_TOKEN" => token.as(String?)}
      else
        env = nil
        argv << "--account" << @account.as(String) if @account
      end

      stdin = input ? IO::Memory.new(input) : Process::Redirect::Close
      output = IO::Memory.new
      status =
        begin
          OpRunner.run(@op_command, argv, env: env, input: stdin, output: output)
        rescue error : OpRunner::TimeoutError
          raise Error.new("op #{arguments.join(" ")} timed out: #{error.message}")
        end
      raise Error.new("op #{arguments.join(" ")} failed (exit #{status.exit_code? || "signal"})") unless status.success?

      output.to_s
    end
  end
end
