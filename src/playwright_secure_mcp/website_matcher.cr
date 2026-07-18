require "uri"
require "./item"

module PlaywrightSecureMcp
  # Ranks 1Password items by how well their URLs match a page URL, requiring an
  # exact normalized host and, when the item URL specifies one, a matching port.
  class WebsiteMatcher
    private record ScoredItem, item : Item, score : Int32
    private record UrlMatch, url : String, score : Int32

    def rank(page_url : String, items : Array(Item)) : Array(Item)
      page = parse_url(page_url)
      return [] of Item if page.nil?
      page_host = normalize_host(page.host)
      page_path = page.path

      scored = [] of ScoredItem
      items.each do |item|
        match = best_match(item, page, page_host, page_path)
        scored << ScoredItem.new(item: prioritize_url(item, match.url), score: match.score) unless match.nil?
      end
      scored.sort_by! { |entry| -entry.score }
      scored.map(&.item)
    end

    # True iff some item URL host-matches the page and its path is root, equal,
    # or a segment-boundary prefix of the page path.
    def matches?(page_url : String, item : Item) : Bool
      page = parse_url(page_url)
      return false if page.nil?
      page_host = normalize_host(page.host)
      page_path = page.path
      item.urls.any? do |raw|
        candidate = parse_url(raw)
        next false if candidate.nil?
        next false unless host_matches?(normalize_host(candidate.host), page_host)
        next false unless port_matches?(candidate, page)
        path_matches?(candidate.path, page_path)
      end
    end

    private def best_match(item : Item, page : URI, page_host : String, page_path : String) : UrlMatch?
      best = nil
      item.urls.each do |raw|
        candidate = parse_url(raw)
        next if candidate.nil?
        next unless host_matches?(normalize_host(candidate.host), page_host)
        next unless port_matches?(candidate, page)
        next unless path_matches?(candidate.path, page_path)
        score = path_score(candidate.path, page_path)
        best = UrlMatch.new(url: raw, score: score) if best.nil? || score > best.score
      end
      best
    end

    # Returns a copy of the item with the matched URL first, so consumers that
    # surface a single URL show the one that actually matched the page.
    private def prioritize_url(item : Item, matched_url : String) : Item
      remaining_urls = item.urls.dup
      matched_index = remaining_urls.index(matched_url)
      remaining_urls.delete_at(matched_index) unless matched_index.nil?
      reordered = item.copy_with(urls: [matched_url] + remaining_urls)
      reordered
    end

    # Parses a URL, prepending a scheme for bare domains like "example.com" so
    # the host is extracted instead of being treated as a path. Returns nil for
    # values op stored that are not valid URIs (e.g. "host:4080 (label)"), so a
    # single malformed item url cannot abort the whole ranking.
    private def parse_url(raw : String) : URI?
      normalized = raw.includes?("://") ? raw : "https://#{raw}"
      URI.parse(normalized)
    rescue URI::Error
      nil
    end

    private def normalize_host(host : String?) : String
      (host || "").downcase.rchop('.')
    end

    private def host_matches?(host : String, page_host : String) : Bool
      return false if host.empty? || page_host.empty?
      host == page_host
    end

    # An item url with an explicit port constrains the page to that port; the
    # page's effective port is its explicit port or the scheme default.
    private def port_matches?(candidate : URI, page : URI) : Bool
      item_port = candidate.port
      return true if item_port.nil?
      item_port == (page.port || default_port(page.scheme))
    end

    private def default_port(scheme : String?) : Int32?
      case scheme
      when "https" then 443
      when "http"  then 80
      else              nil
      end
    end

    # Matches only on a path-segment boundary, so "/admin" matches
    # "/admin/login" but not "/administrator". Root and empty item paths match
    # every page path.
    private def path_matches?(item_path : String, page_path : String) : Bool
      return true if item_path.empty? || item_path == "/"
      page_path == item_path || page_path.starts_with?("#{item_path}/")
    end

    # Scores a matching path by its length; root and non-prefix paths both score
    # zero, so the boolean question is answered by `path_matches?`, never here.
    private def path_score(item_path : String, page_path : String) : Int32
      path_matches?(item_path, page_path) ? item_path.size : 0
    end
  end
end
