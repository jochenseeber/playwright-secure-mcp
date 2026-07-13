require "base64"
require "uri"
require "html"
require "json"
require "./secret_vault"

module PlaywrightSecureMcp
  class Redactor
    TOKEN = "«REDACTED»"

    def initialize(@vault : SecretVault)
    end

    def redact(text : String) : String
      result = text
      @vault.each_plaintext do |secret|
        variants(secret).each do |variant|
          result = result.gsub(variant, TOKEN)
        end
      end
      result
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
