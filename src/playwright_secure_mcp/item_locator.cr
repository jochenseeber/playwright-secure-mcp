require "json"
require "./encrypted_secret"
require "./item"
require "./item_cache"
require "./op_item"
require "./op_runner"

module PlaywrightSecureMcp
  # Looks up LOGIN items via the `op` CLI. Listing returns non-secret summaries
  # (no `--reveal`); `reveal` batch-fetches full items with their (encrypted)
  # field values. All results are restricted to category LOGIN.
  class ItemLocator
    class Error < Exception
    end

    LOGIN_CATEGORY = "LOGIN"

    # Field types/purposes that hold an actual credential. Only these fields'
    # values are cached (encrypted) and thus fed to the redactor and guard;
    # other fields (form artifacts like language pickers or submit buttons)
    # are surfaced as metadata only, so their non-secret values never trigger
    # over-redaction of unrelated page content.
    CONCEALED_TYPE      = "CONCEALED"
    OTP_TYPE            = "OTP"
    CREDENTIAL_PURPOSES = {"USERNAME", "PASSWORD"}

    def initialize(*, @op_command : String, @account : String?, @encryptor : ItemCache)
    end

    def list_logins(vault : String?) : Array(Item)
      output = run(["item", "list", "--categories", "Login", "--format=json"], vault: vault)
      op_items(output).map { |op| summary(op) }
    end

    def list_by_tag(tag : String, vault : String?) : Array(Item)
      output = run(["item", "list", "--categories", "Login", "--tags", tag, "--format=json"], vault: vault)
      op_items(output).map { |op| summary(op) }
    end

    # One batched `op item get - --reveal`: specifiers piped as a JSON array on
    # stdin. Returns full items; silently drops any whose category != LOGIN.
    def reveal(keys : Array(ItemKey)) : Array(Item)
      return [] of Item if keys.empty?
      specifiers = keys.map { |k| {"id" => k.item_id, "vault" => {"id" => k.vault_id}} }.to_json
      output = run(["item", "get", "-", "--reveal", "--format=json"], vault: nil, input: specifiers)
      op_items(output).select { |op| op.category == LOGIN_CATEGORY }.map { |op| full(op) }
    end

    # Fetches the item's current one-time password live. The code is a
    # short-lived secret: it is never cached for reuse and never placed on a
    # command line (op prints it to stdout).
    def one_time_password(key : ItemKey) : String
      code = run(["item", "get", key.item_id, "--otp"], vault: key.vault_id).strip
      raise Error.new("op returned no one-time password for #{key.item_id}") if code.empty?
      code
    end

    # Parse op's output: a single JSON array, or a stream of concatenated
    # top-level objects (op item get - for several items). Splits into raw JSON
    # segments and parses each with the DTO.
    private def op_items(output : String) : Array(OpItem)
      trimmed = output.strip
      return [] of OpItem if trimmed.empty?
      if trimmed.starts_with?('[')
        Array(OpItem).from_json(trimmed)
      else
        split_json_segments(trimmed).map { |segment| OpItem.from_json(segment) }
      end
    rescue error : JSON::ParseException | JSON::SerializableError
      raise Error.new("op returned malformed item JSON: #{error.message}")
    end

    private def summary(op : OpItem) : Item
      Item.new(
        key: ItemKey.new(vault_id: op.vault.id, item_id: op.id),
        title: op.title || "",
        urls: op.urls.compact_map(&.href),
        tags: op.tags,
        fields: {} of String => Field,
        sections: {} of String => Section)
    end

    private def full(op : OpItem) : Item
      sections = {} of String => Section
      op.sections.each do |section|
        id = section.id
        next if id.nil?
        sections[id] = Section.new(id: id, label: section.label || "")
      end

      fields = {} of String => Field
      op.fields.each do |field|
        id = field.id
        next if id.nil?
        type = field.type || ""
        purpose = field.purpose
        fields[id] = Field.new(
          id: id,
          section_id: field.section.try(&.id),
          type: type,
          purpose: purpose,
          label: field.label || "",
          value: cache_value(type: type, purpose: purpose, value: field.value))
      end

      Item.new(
        key: ItemKey.new(vault_id: op.vault.id, item_id: op.id),
        title: op.title || "",
        urls: op.urls.compact_map(&.href),
        tags: op.tags,
        fields: fields,
        sections: sections)
    end

    private def split_json_segments(output : String) : Array(String)
      segments = [] of String
      depth = 0
      in_string = false
      escape = false
      start = -1
      output.each_char_with_index do |char, index|
        if start < 0
          next if char.whitespace?
          start = index
        end
        if in_string
          in_string, escape = scan_string_char(char, escape)
        else
          case char
          when '"'      then in_string = true
          when '{', '[' then depth += 1
          when '}', ']'
            depth -= 1
            if depth == 0
              segments << output[start..index]
              start = -1
            end
          end
        end
      end
      segments
    end

    # Advances the string-literal scan by one character, returning the next
    # {in_string, escape} state.
    private def scan_string_char(char : Char, escape : Bool) : Tuple(Bool, Bool)
      return {true, false} if escape
      return {true, true} if char == '\\'
      {char != '"', false}
    end

    # Encrypts a field value only when the field holds a credential; otherwise
    # returns nil so the value is neither typable nor redacted.
    private def cache_value(*, type : String, purpose : String?, value : String?) : EncryptedSecret?
      return nil if value.nil? || value.empty?
      return nil if type == OTP_TYPE
      return nil unless type == CONCEALED_TYPE || (purpose && CREDENTIAL_PURPOSES.includes?(purpose))
      @encryptor.encrypt(value)
    end

    # Runs `op` with either the service-account token decrypted transiently
    # into the child environment (no `--account`), or `--account` when no
    # token is stored. The plaintext token lives only for the op call.
    private def run(arguments : Array(String), *, vault : String?, input : String? = nil) : String
      argv = arguments.dup
      argv << "--vault" << vault if vault
      if @encryptor.service_token?
        @encryptor.with_service_token do |token|
          invoke(arguments, argv, {"OP_SERVICE_ACCOUNT_TOKEN" => token.as(String?)}, input)
        end
      else
        argv << "--account" << @account.as(String) if @account
        invoke(arguments, argv, nil, input)
      end
    end

    private def invoke(arguments : Array(String), argv : Array(String), env : Process::Env, input : String?) : String
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
