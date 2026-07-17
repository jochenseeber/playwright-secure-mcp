require "json"
require "./item"
require "./item_cache"
require "./op_runner"

module PlaywrightSecureMcp
  # Looks up LOGIN items via the `op` CLI. Listing returns non-secret summaries
  # (no `--reveal`); `reveal` batch-fetches full items with their (encrypted)
  # field values. All results are restricted to category LOGIN.
  class ItemLocator
    class Error < Exception
    end

    LOGIN_CATEGORY = "LOGIN"

    def initialize(*, @op_command : String, @account : String?,
                   @service_account_token : String? = nil, @encryptor : ItemCache)
    end

    def list_logins(vault : String?) : Array(Item)
      output = run(["item", "list", "--categories", "Login", "--format=json"], vault: vault)
      summaries(output)
    end

    def list_by_tag(tag : String, vault : String?) : Array(Item)
      output = run(["item", "list", "--categories", "Login", "--tags", tag, "--format=json"], vault: vault)
      summaries(output)
    end

    # One batched `op item get - --reveal`: specifiers piped as a JSON array on
    # stdin. Returns full items; silently drops any whose category != LOGIN.
    def reveal(keys : Array(ItemKey)) : Array(Item)
      return [] of Item if keys.empty?
      specifiers = keys.map { |k| {"id" => k.item_id, "vault" => {"id" => k.vault_id}} }.to_json
      output = run(["item", "get", "-", "--reveal", "--format=json"], vault: nil, input: specifiers)
      parse_full(output)
    end

    private def summaries(output : String) : Array(Item)
      parse(output).map { |entry| summary_from(entry) }
    rescue error : TypeCastError
      raise Error.new("op returned a malformed item list: #{error.message}")
    end

    private def parse_full(output : String) : Array(Item)
      parse(output).compact_map do |entry|
        next nil unless entry["category"]?.try(&.as_s?) == LOGIN_CATEGORY
        full_from(entry)
      end
    rescue error : TypeCastError
      raise Error.new("op returned a malformed item: #{error.message}")
    end

    # `op item get -` returns a single object for one specifier, an array for
    # several; normalize to an array.
    private def parse(output : String) : Array(JSON::Any)
      parsed = JSON.parse(output)
      parsed.as_a? || [parsed]
    end

    private def summary_from(entry : JSON::Any) : Item
      Item.new(
        key: key_of(entry),
        title: entry["title"]?.try(&.as_s) || "",
        urls: urls_of(entry),
        tags: tags_of(entry),
        fields: {} of String => Field,
        sections: {} of String => Section)
    rescue error : KeyError | TypeCastError | NilAssertionError
      raise Error.new("op returned a malformed item: #{error.message}")
    end

    private def full_from(entry : JSON::Any) : Item
      Item.new(key: key_of(entry), title: entry["title"]?.try(&.as_s) || "",
        urls: urls_of(entry), tags: tags_of(entry),
        fields: fields_of(entry), sections: sections_of(entry))
    rescue error : KeyError | TypeCastError | NilAssertionError
      raise Error.new("op returned a malformed item: #{error.message}")
    end

    private def sections_of(entry : JSON::Any) : Hash(String, Section)
      sections = {} of String => Section
      (entry["sections"]?.try(&.as_a) || [] of JSON::Any).each do |raw|
        id = raw["id"]?.try(&.as_s)
        next if id.nil?
        sections[id] = Section.new(id: id, label: raw["label"]?.try(&.as_s) || "")
      end
      sections
    end

    private def fields_of(entry : JSON::Any) : Hash(String, Field)
      fields = {} of String => Field
      (entry["fields"]?.try(&.as_a) || [] of JSON::Any).each do |raw|
        id = raw["id"]?.try(&.as_s)
        next if id.nil?
        raw_value = raw["value"]?.try(&.as_s)
        fields[id] = Field.new(
          id: id,
          section_id: raw.dig?("section", "id").try(&.as_s),
          type: raw["type"]?.try(&.as_s) || "",
          purpose: raw["purpose"]?.try(&.as_s),
          label: raw["label"]?.try(&.as_s) || "",
          value: (raw_value && !raw_value.empty?) ? @encryptor.encrypt(raw_value) : nil)
      end
      fields
    end

    private def key_of(entry : JSON::Any) : ItemKey
      ItemKey.new(vault_id: entry["vault"]["id"].as_s, item_id: entry["id"].as_s)
    end

    private def urls_of(entry : JSON::Any) : Array(String)
      entry["urls"]?.try(&.as_a.compact_map(&.["href"]?.try(&.as_s))) || [] of String
    end

    private def tags_of(entry : JSON::Any) : Array(String)
      entry["tags"]?.try(&.as_a.compact_map(&.as_s?)) || [] of String
    end

    private def run(arguments : Array(String), *, vault : String?, input : String? = nil) : String
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
