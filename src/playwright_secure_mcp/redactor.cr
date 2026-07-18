require "base64"
require "uri"
require "html"
require "json"
require "./item_cache"

module PlaywrightSecureMcp
  class Redactor
    TOKEN = "«REDACTED»"

    def initialize(@cache : ItemCache)
    end

    # Redacts secrets only within the string leaves of a JSON value, leaving the
    # structure intact. Redacting the serialized form directly can corrupt the
    # JSON when a secret is (or contains) a structural character — a comma,
    # quote, colon, or brace — which desynchronizes the client's stream, so all
    # client-bound and logged JSON is redacted through this.
    def redact(value : JSON::Any) : JSON::Any
      case raw = value.raw
      when String
        JSON::Any.new(redact(raw))
      when Array(JSON::Any)
        JSON::Any.new(raw.map { |element| redact(element) })
      when Hash(String, JSON::Any)
        JSON::Any.new(raw.transform_values { |element| redact(element) })
      else
        value
      end
    end

    def redact(text : String) : String
      result = text
      @cache.each_plaintext do |secret|
        variants(secret).each do |variant|
          result = result.gsub(variant, TOKEN)
        end
      end
      result
    end

    # Formats an exception for a log line with any cached secret in its message
    # masked. The class name and backtrace frames (file:line) carry no secret
    # values; only the message is redacted.
    def redact_exception(error : Exception) : String
      message = redact(error.message || "")
      backtrace = error.backtrace?.try(&.join("\n"))
      if backtrace
        "#{error.class}: #{message}\n#{backtrace}"
      else
        "#{error.class}: #{message}"
      end
    end

    # The longest redactable form of any cached secret, in characters. A
    # consumer that redacts a stream in bounded chunks uses this to size an
    # overlap window, so a secret spanning a chunk boundary is never emitted
    # split below the length at which the redactor could still match it.
    def max_secret_length : Int32
      longest = 0
      @cache.each_plaintext do |secret|
        variants(secret).each do |variant|
          longest = variant.size if variant.size > longest
        end
      end
      longest
    end

    private def variants(secret : String) : Array(String)
      json_escaped = secret.to_json[1..-2]
      candidates = [
        secret,
        URI.encode_www_form(secret),                       # space -> '+'
        URI.encode_www_form(secret, space_to_plus: false), # space -> '%20'
        Base64.strict_encode(secret),
        Base64.urlsafe_encode(secret),
        HTML.escape(secret),
        json_escaped,
      ]
      candidates.reject(&.empty?).uniq!
    end
  end
end
