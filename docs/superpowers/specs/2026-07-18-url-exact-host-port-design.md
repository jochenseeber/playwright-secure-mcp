# Tighten URL authorization to exact host + port (F2) — design

Date: 2026-07-18

## Goal

Fix security-review finding **F2**: `WebsiteMatcher`'s host matching is
overbroad — it accepts subdomains in both directions and ignores ports, so a
credential can be typed into an unintended origin (a parent domain, a sibling
tenant under a public suffix like `attacker.github.io`, or a different port).
Replace the subdomain logic with **exact host matching**, and enforce a **port
match when the item URL specifies a port**.

Scope note: the HTTP/HTTPS (scheme downgrade) sub-issue of F2 is **explicitly
out of scope** for this change (per direction). It remains an open item in the
review. Path matching is unchanged.

## Current behavior (the bug)

[`WebsiteMatcher#same_site?`](../../src/playwright_secure_mcp/website_matcher.cr)
returns true for exact host, page-as-subdomain, **and** item-as-subdomain, and
`matches?`/`best_match` compare only host + path — ports are ignored.
Consequences from the review:

- `https://login.example.com` (item) authorizes `https://example.com` (page) —
  reverse subdomain.
- `https://github.io` (item) authorizes `https://attacker.github.io` (page) —
  cross-tenant public suffix.
- `https://example.com:8443` (item) authorizes `https://example.com:443` (page)
  — port ignored.

## Design

Change the host predicate and add a port predicate; leave URL parsing, path
matching, ranking, and `prioritize_url` as they are.

### Host: literal exact match

Replace `same_site?(host, page_host)` with exact equality of the **normalized**
hosts. `normalize_host` now only **lowercases** and strips a single **trailing
`.`** (FQDN dot). The current leading-`www.` stripping is **removed** —
matching is literal-exact. Effect:

- `www.example.com` ≠ `example.com` (`www.` is a distinct host and is not
  folded; an item and page must share the exact host).
- `login.example.com` ≠ `example.com` (no subdomain inheritance, either
  direction).
- `github.io` ≠ `attacker.github.io` (public-suffix cross-tenant rejected as a
  natural consequence of exact matching — no PSL needed).

Rename `same_site?` to `host_matches?` to reflect the new semantics.

### Port: match when the item URL specifies one

Add `port_matches?(item_uri, page_uri)`:

- If the **item** URL has **no explicit port** (`item_uri.port.nil?`), the port
  is unconstrained — return true.
- If the item URL has an explicit port, require the page's **effective** port
  to equal it, where effective port = `uri.port || default_port(uri.scheme)`
  (`https` → 443, `http` → 80, else `nil`). So `:8443` (item) rejects `:443`
  (page), and `:443` (item) accepts a page with no explicit `https` port.

### Where it plugs in

Both `matches?` and `best_match` gain the port check alongside the host check:
an item URL matches the page only when `host_matches?` **and** `port_matches?`
**and** `path_matches?`. Both parse the item URL (already done via `parse_url`)
to obtain host and port. `matches?` is the authorization gate used by
`browser_type_secret`; `best_match`/`rank` is used by discovery — both must
apply the same tightened rule so discovery does not surface an item that typing
would then refuse.

## Behavior impact (intended)

This is a deliberate tightening: some previously-matching real cases stop
matching. A stored URL on a different subdomain than the page no longer matches
(e.g. `shop.example.com` item vs a `www.example.com` page), and — because
`www.` is no longer folded — an item stored as `www.example.com` no longer
matches a bare `example.com` page (or vice-versa). This is the correct, safer
behavior; users whose items use a different host than the page must store the
page's exact host on the item.

## Files

- Modify: `src/playwright_secure_mcp/website_matcher.cr` — replace `same_site?`
  with exact `host_matches?`, add `port_matches?` + `default_port`, change
  `normalize_host` to drop the leading-`www.` stripping and add trailing-dot
  stripping, apply the port check in `matches?` and `best_match`.
- Modify: `spec/website_matcher_spec.cr` — table-driven cases (below).

## Testing

Table-driven `matches?` cases:

- Exact host: `https://example.com` item ⇔ `https://example.com/login` page →
  match.
- No `www` folding: item `https://www.example.com` ⇔ page `https://example.com`
  → no match (and vice-versa); item `https://www.example.com` ⇔ page
  `https://www.example.com` → match.
- Reject page-subdomain: item `https://example.com` ⇔ page
  `https://login.example.com` → no match.
- Reject reverse subdomain: item `https://login.example.com` ⇔ page
  `https://example.com` → no match.
- Reject cross-tenant public suffix: item `https://github.io` ⇔ page
  `https://attacker.github.io` → no match.
- Port specified, equal: item `https://example.com:8443` ⇔ page
  `https://example.com:8443/x` → match.
- Port specified, unequal: item `https://example.com:8443` ⇔ page
  `https://example.com` (:443) → no match.
- Port specified as default: item `https://example.com:443` ⇔ page
  `https://example.com` → match (effective port).
- Item without port: item `https://example.com` ⇔ page
  `https://example.com:8443` → match (port unconstrained).
- Trailing dot: item `https://example.com.` ⇔ page `https://example.com` →
  match.
- Path still enforced: item `https://example.com/app` ⇔ page
  `https://example.com/other` → no match (unchanged).

Keep existing ranking/path specs green (adjust any that relied on subdomain
matching to use exact hosts, and note the behavior change).

`rake spec` / `rake lint` / `rake build` all green.

## Out of scope

- Scheme/HTTP-downgrade enforcement (F2 #1) — disregarded per direction.
- Public Suffix List integration — unnecessary once matching is exact-host.
- IDNA/punycode normalization, IP-address canonicalization — not requested;
  exact string host comparison is applied to whatever host `URI` yields.
- Any change to discovery scope, caching, or redaction.
