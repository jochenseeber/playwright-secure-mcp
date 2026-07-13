require "uri"
require "./item"

module PlaywrightSecureMcp
  # Ranks 1Password items by how well their URLs match a page URL, mirroring the
  # 1Password browser extension's domain matching without a Public Suffix List.
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
        match = best_match(item, page_host, page_path)
        scored << ScoredItem.new(item: prioritize_url(item, match.url), score: match.score) unless match.nil?
      end
      scored.sort_by! { |entry| -entry.score }
      scored.map(&.item)
    end

    private def best_match(item : Item, page_host : String, page_path : String) : UrlMatch?
      best = nil
      item.urls.each do |raw|
        candidate = parse_url(raw)
        next if candidate.nil?
        next unless same_site?(normalize_host(candidate.host), page_host)
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
      value = (host || "").downcase
      value = value["www.".size..] if value.starts_with?("www.")
      value
    end

    private def same_site?(host : String, page_host : String) : Bool
      return false if host.empty? || page_host.empty?
      equal = host == page_host
      page_is_subdomain = page_host.ends_with?(".#{host}")
      item_is_subdomain = host.ends_with?(".#{page_host}")
      equal || page_is_subdomain || item_is_subdomain
    end

    # Scores a match only on a path-segment boundary, so "/admin" matches
    # "/admin/login" but not "/administrator". Root and empty item paths match
    # every page path at their natural low score.
    private def path_score(item_path : String, page_path : String) : Int32
      root = item_path.empty? || item_path == "/"
      matched = root || page_path == item_path || page_path.starts_with?("#{item_path}/")
      score = matched ? item_path.size : 0
      score
    end
  end
end
