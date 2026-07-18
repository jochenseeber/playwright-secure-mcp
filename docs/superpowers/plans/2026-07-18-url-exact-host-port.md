# URL exact host + port matching (F2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tighten `WebsiteMatcher` so a 1Password item authorizes a page only
on an **exact host** and a matching **port** (when the item URL specifies one),
fixing security finding F2 (overbroad subdomain/public-suffix/port matching).

**Architecture:** Replace `same_site?`'s bidirectional subdomain logic with
exact normalized-host equality, drop `www.` folding, add trailing-dot
stripping, and add a port predicate applied in both the `matches?`
authorization gate and the `best_match`/`rank` discovery path.

**Tech Stack:** Crystal ≥ 1.20 (`URI` stdlib), Spectator specs.

## Global Constraints

- Crystal `>= 1.20`; edit with Write/Edit (never Serena symbol editing).
- Host matching is **literal exact** after normalization (lowercase + strip one
  trailing `.`); `www.` is **not** folded; no subdomain inheritance in either
  direction; no Public Suffix List needed.
- Port: if the **item** URL has an explicit port, the page's **effective** port
  (explicit, else scheme default 443/80) must equal it; if the item URL has no
  explicit port, port is unconstrained.
- Path matching unchanged (segment-boundary prefix). Scheme/HTTP-downgrade is
  **out of scope**.
- `matches?` (typing authorization) and `best_match`/`rank` (discovery) must
  apply the identical host+port+path rule.
- `rake spec` / `rake lint` / `rake build` all green.
- Commit: Conventional `fix:` (security fix), body an unordered bullet list ≤72
  cols, no AI/Claude/Copilot references. ONE commit.
- Ad-hoc `crystal spec` needs `--link-flags=-fuse-ld=/usr/bin/ld`; rake handles
  it.

---

### Task 1: Exact host + port matching in WebsiteMatcher

**Files:**

- Modify: `src/playwright_secure_mcp/website_matcher.cr`
- Test: `spec/website_matcher_spec.cr`

**Interfaces:**

- Public `matches?(page_url : String, item : Item) : Bool` and
  `rank(page_url : String, items : Array(Item)) : Array(Item)` — signatures
  unchanged; behavior tightened.

- [ ] **Step 1: Rewrite the two behavior-changing specs and add the F2 table**

In `spec/website_matcher_spec.cr`, **replace** the two tests that assert the
old loose behavior:

Replace the `"matches on exact host ignoring www"` test (currently item
`https://www.example.com` matching page `https://example.com`) with:

```crystal
it "matches only on the exact host, without folding www" do
  items = [item("a", "https://www.example.com"), item("b", "https://other.com")]
  # www.example.com is a distinct host from example.com now.
  expect(matcher.rank("https://example.com/login", items).map(&.item_id)).to be_empty
  expect(matcher.rank("https://www.example.com/login", items).map(&.item_id)).to eq(["a"])
end
```

Replace the `"matches a subdomain page against a parent-domain item"` test
with:

```crystal
it "does not authorize a subdomain page from a parent-domain item" do
  items = [item("a", "https://google.com")]
  expect(matcher.rank("https://accounts.google.com/signin", items)).to be_empty
end
```

Then **append** the F2 table-driven cases inside the same `describe` block:

```crystal
  it "rejects reverse subdomain (child item, parent page)" do
    candidate = item("i", "https://login.example.com")
    expect(matcher.matches?("https://example.com/", candidate)).to be_false
  end

  it "rejects cross-tenant public suffixes" do
    candidate = item("i", "https://github.io")
    expect(matcher.matches?("https://attacker.github.io/x", candidate)).to be_false
  end

  it "requires the page port to match an item url that specifies one" do
    candidate = item("i", "https://example.com:8443")
    expect(matcher.matches?("https://example.com:8443/x", candidate)).to be_true
    expect(matcher.matches?("https://example.com/x", candidate)).to be_false      # :443 != :8443
  end

  it "treats an item port equal to the scheme default as matching a portless page" do
    candidate = item("i", "https://example.com:443")
    expect(matcher.matches?("https://example.com/x", candidate)).to be_true
  end

  it "leaves the port unconstrained when the item url has no port" do
    candidate = item("i", "https://example.com")
    expect(matcher.matches?("https://example.com:8443/x", candidate)).to be_true
  end

  it "normalizes a trailing dot on the host" do
    candidate = item("i", "https://example.com.")
    expect(matcher.matches?("https://example.com/x", candidate)).to be_true
  end
```

(Keep the existing path-ranking, `prioritize_url`, partial-segment,
bare-scheme, empty-result, unparseable, and `matches?` path tests — they all
use the exact host `example.com` and stay green.)

- [ ] **Step 2: Run — FAIL**

Run:
`crystal spec spec/website_matcher_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: FAIL — the rewritten www/subdomain tests fail against the current
loose matcher, and the port/reverse-subdomain/public-suffix cases fail (port
ignored, `same_site?` accepts subdomains).

- [ ] **Step 3: Implement the tightened matcher**

In `src/playwright_secure_mcp/website_matcher.cr`:

(a) Thread the parsed page `URI` into `best_match` so it can see the port:

```crystal
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
```

(b) `matches?` — add the port check:

```crystal
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
```

(c) `best_match` — take the page `URI` and add the port check:

```crystal
private def best_match(item : Item, page : URI, page_host : String, page_path : String) : UrlMatch?
  best = nil
  item.urls.each do |raw|
    candidate = parse_url(raw)
    next if candidate.nil?
    next unless host_matches?(normalize_host(candidate.host), page_host)
    next unless port_matches?(candidate, page)
    score = path_score(candidate.path, page_path)
    best = UrlMatch.new(url: raw, score: score) if best.nil? || score > best.score
  end
  best
end
```

(d) `normalize_host` — drop `www.` stripping, strip a trailing dot:

```crystal
private def normalize_host(host : String?) : String
  (host || "").downcase.rchop('.')
end
```

(e) Replace `same_site?` with exact `host_matches?`, and add the port helpers:

```crystal
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
```

Delete the old `same_site?`.

- [ ] **Step 4: Run — PASS**

Run:
`crystal spec spec/website_matcher_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS.

- [ ] **Step 5: Full gate + commit**

Run: `rake spec && rake lint && rake build` Expected: all green. (The
proxy/finder specs use `example.com` exact hosts, so they stay green; if any
relied on subdomain/www matching, update them to exact hosts — none are
expected to.)

```bash
git add src/playwright_secure_mcp/website_matcher.cr spec/website_matcher_spec.cr
git commit  # fix: authorize secret typing only on exact host and matching port  (+ bullet body)
```

---

## Self-review notes

- **Spec coverage:** exact host (host_matches?), drop www (normalize_host),
  trailing dot (normalize_host + test), reverse/parent subdomain reject
  (tests), public-suffix cross-tenant reject (test), port when specified +
  effective-port default + unconstrained-when-absent (port_matches? + tests),
  applied in both `matches?` and `best_match` (both edited). Scheme out of
  scope. All covered.
- **Type consistency:** `best_match` now takes `page : URI` (rank updated to
  pass it); `host_matches?(String, String)`, `port_matches?(URI, URI)`,
  `default_port(String?) : Int32?`. `matches?`/`rank` public signatures
  unchanged.
- **Behavior change:** the two rewritten specs document the intended tightening
  (no www folding, no subdomain inheritance).
