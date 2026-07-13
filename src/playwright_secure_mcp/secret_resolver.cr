require "json"
require "./op_runner"

module PlaywrightSecureMcp
  class SecretResolver
    class Error < Exception
    end

    class InvalidReferenceError < Error
    end

    class ResolutionError < Error
    end

    REFERENCE_PREFIX = "op://"

    # The 1Password field purposes for the standard login fields, so username and
    # password can be selected by purpose rather than by label.
    FIELD_PURPOSES = {"username" => "USERNAME", "password" => "PASSWORD"}

    def initialize(*, @op_command : String, @account : String? = nil, @service_account_token : String? = nil)
    end

    def resolve(reference : String) : String
      unless reference.starts_with?(REFERENCE_PREFIX)
        raise InvalidReferenceError.new("1Password reference must start with #{REFERENCE_PREFIX}")
      end

      from_item = resolve_from_item(reference)
      return from_item if from_item

      resolve_by_read(reference)
    end

    # Resolve a plain vault/item/field reference by reading the item and choosing
    # the best matching field. Preference order: a field whose purpose is the
    # standard one (for username/password), then a non-empty value over an empty
    # one, then a field with an id over one without. This avoids losing a value
    # to a same-labelled artifact field (e.g. empty form-capture duplicates).
    # Returns nil — so the caller falls back to `op read` — when the reference is
    # not a plain vault/item/field, the item cannot be read, or no matching field
    # has a value.
    private def resolve_from_item(reference : String) : String?
      segments = reference[REFERENCE_PREFIX.size..].split('/')
      return nil unless segments.size == 3 && segments.none?(&.empty?)

      vault, item, field = segments
      document = read_item(vault: vault, item: item)
      return nil if document.nil?

      fields = document["fields"]?.try(&.as_a?)
      return nil if fields.nil?

      purpose = FIELD_PURPOSES[field]?
      candidates = fields.select { |candidate| matches_field?(candidate, field: field, purpose: purpose) }
      best = candidates.max_by? { |candidate| field_rank(candidate, purpose: purpose) }
      return nil if best.nil?

      value = best["value"]?.try(&.as_s?)
      value if value && !value.empty?
    end

    private def matches_field?(candidate : JSON::Any, *, field : String, purpose : String?) : Bool
      candidate["id"]?.try(&.as_s?) == field ||
        candidate["label"]?.try(&.as_s?) == field ||
        (!purpose.nil? && candidate["purpose"]?.try(&.as_s?) == purpose)
    end

    # Ranking key (compared as a tuple, highest wins): purpose match, then a
    # non-empty value, then the presence of an id.
    private def field_rank(candidate : JSON::Any, *, purpose : String?) : Tuple(Int32, Int32, Int32)
      purpose_match = !purpose.nil? && candidate["purpose"]?.try(&.as_s?) == purpose
      value = candidate["value"]?.try(&.as_s?)
      id = candidate["id"]?.try(&.as_s?)
      {
        purpose_match ? 1 : 0,
        (value && !value.empty?) ? 1 : 0,
        (id && !id.empty?) ? 1 : 0,
      }
    end

    # The {env, extra args} that carry the account/service-account context to op:
    # a service-account token via the environment (no --account), otherwise the
    # configured account via --account, otherwise op's default account.
    private def op_context : Tuple(Process::Env, Array(String))
      if token = @service_account_token
        env = {"OP_SERVICE_ACCOUNT_TOKEN" => token.as(String?)}
        {env, [] of String}
      elsif account = @account
        {nil, ["--account", account]}
      else
        {nil, [] of String}
      end
    end

    # The parsed JSON of `op item get`, or nil when op fails or returns non-JSON.
    private def read_item(*, vault : String, item : String) : JSON::Any?
      env, account_args = op_context
      args = ["item", "get", item, "--vault", vault, "--reveal", "--format=json"] + account_args

      output = IO::Memory.new
      status =
        begin
          OpRunner.run(@op_command, args, env: env, output: output)
        rescue OpRunner::TimeoutError
          return nil
        end
      return nil unless status.success?

      begin
        JSON.parse(output.to_s)
      rescue JSON::ParseException
        nil
      end
    end

    private def resolve_by_read(reference : String) : String
      env, account_args = op_context
      args = ["read"] + account_args
      args << reference

      output = IO::Memory.new
      status =
        begin
          OpRunner.run(@op_command, args, env: env, output: output)
        rescue error : OpRunner::TimeoutError
          raise ResolutionError.new("timed out resolving 1Password reference: #{error.message}")
        end
      unless status.success?
        raise ResolutionError.new("failed to resolve 1Password reference (op exited with #{status.exit_code? || "signal"})")
      end

      output.to_s.chomp
    end
  end
end
