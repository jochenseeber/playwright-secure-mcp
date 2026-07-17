require "json"

module PlaywrightSecureMcp
  # Reads the current page URL by asking the upstream server to evaluate
  # `location.href`. The actual upstream round-trip is supplied by the caller so
  # this stays decoupled from Proxy internals.
  class PageUrl
    class UnavailableError < Exception
    end

    EVALUATE_TOOL = "browser_evaluate"

    # A whole line that is nothing but a URL (after unquoting).
    URL_LINE_PATTERN = %r{\A[A-Za-z][A-Za-z0-9+.\-]*://\S+\z}
    # A URL token embedded in surrounding text; quotes/backticks excluded so
    # the match ends before a closing quote.
    URL_TOKEN_PATTERN = %r{[A-Za-z][A-Za-z0-9+.\-]*://[^\s"'`]+}
    # Characters trimmed from around a candidate URL.
    WRAPPER_CHARACTERS = "\"'` "

    def current(& : JSON::Any -> JSON::Any) : String
      params = JSON::Any.new({
        "name"      => JSON::Any.new(EVALUATE_TOOL),
        "arguments" => JSON::Any.new({"function" => JSON::Any.new("() => location.href")}),
      })
      response = yield params
      url = extract(response)
      raise UnavailableError.new("could not determine the current page URL") if url.nil? || url.strip.empty?
      url.strip
    end

    # Defensive: a scalar or otherwise malformed upstream response must yield
    # nil (fail closed as UnavailableError), never raise a bare exception.
    private def extract(response : JSON::Any) : String?
      return nil if response.as_h?.nil?
      return nil unless response["error"]?.nil?
      return nil if response.dig?("result", "isError").try(&.as_bool?) == true
      content = response.dig?("result", "content").try(&.as_a?)
      return nil if content.nil?
      texts = content.compact_map { |part| part.as_h?.nil? ? nil : part["text"]?.try(&.as_s?) }
      return nil if texts.empty?
      url = find_url(texts.join('\n'))
      url
    end

    # The real upstream (@playwright/mcp) returns the evaluated value
    # JSON-stringified and wrapped in a markdown reply (### headings, ```
    # fences, extra sections); the older/fake format is the bare URL. Recover
    # the URL from any of these shapes; nil when none is found (fail closed).
    private def find_url(text : String) : String?
      lines = text.lines.map(&.strip).reject do |line|
        line.starts_with?("#") || line.starts_with?("```")
      end
      lines.each do |line|
        next if line.empty?
        candidate = unquote(line).strip(WRAPPER_CHARACTERS)
        return candidate if candidate.matches?(URL_LINE_PATTERN)
      end
      embedded = lines.compact_map { |line| line.match(URL_TOKEN_PATTERN).try(&.[0]) }.first?
      embedded
    end

    # A JSON-stringified value like "https://..." parses to its inner string;
    # anything that is not valid JSON is returned untouched.
    private def unquote(line : String) : String
      parsed = JSON.parse(line).as_s?
      parsed || line
    rescue JSON::ParseException
      line
    end
  end
end
