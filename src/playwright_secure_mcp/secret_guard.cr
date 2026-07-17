require "json"
require "./item_cache"
require "./secret_type_tool"

module PlaywrightSecureMcp
  # Rejects tool arguments that carry an op:// reference or a resolved secret,
  # so secrets can only travel through the dedicated secret-typing tool.
  class SecretGuard
    class ViolationError < Exception
    end

    REFERENCE_PREFIX = "op://"

    def initialize(@cache : ItemCache)
    end

    def check(arguments : JSON::Any) : Nil
      strings = [] of String
      collect_strings(arguments, strings)
      check_references(strings)
      check_plaintexts(strings)
    end

    private def collect_strings(value : JSON::Any, strings : Array(String)) : Nil
      case raw = value.raw
      when String
        strings << raw
      when Array(JSON::Any)
        raw.each { |element| collect_strings(element, strings) }
      when Hash(String, JSON::Any)
        raw.each_value { |element| collect_strings(element, strings) }
      end
    end

    private def check_references(strings : Array(String)) : Nil
      return unless strings.any?(&.includes?(REFERENCE_PREFIX))
      raise ViolationError.new("op:// secret references may only be passed to #{SecretTypeTool::NAME}")
    end

    private def check_plaintexts(strings : Array(String)) : Nil
      @cache.each_plaintext do |secret|
        next if secret.empty?
        if strings.any?(&.includes?(secret))
          raise ViolationError.new("resolved secret values must not be sent to upstream tools; use #{SecretTypeTool::NAME}")
        end
      end
    end
  end
end
