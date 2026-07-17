# Item cache + LOGIN scope + URL-bound typing — design

Date: 2026-07-17

## Goal

Rework the in-memory credentials cache to hold structured **item objects**
(keyed by vault + item id), each carrying its fields (with encrypted values),
sections, URLs, and tags. Tighten the MCP so it only ever accesses 1Password
items of category **LOGIN**; discovery tools only surface items valid for the
**current browser page**; and a secret is only typed into a page whose URL is
in the item's URL set (closing the confused-deputy risk from the security
review, finding H2). Adds a `browser_list_items` tool that lists the LOGIN
items usable on the current page.

## Current state (for context)

- `SecretVault` maps `SHA256("op://vault/item/field") → EncryptedSecret`; the
  cipher (Secure Enclave / TPM / keyring / in-memory) encrypts each secret
  string.
- Discovery tools (`ItemLocator`, `secret_finders.cr`) call `op` **without**
  `--reveal` and return only identities.
- `SecretResolver` reveals a value just-in-time at type time
  (`op item get
  --reveal` / `op read`).
- `Proxy#handle_secret_call` resolves `op://vault/item/field`, injects an
  upstream `browser_type` with the plaintext, and redacts responses.
- `Redactor` / `SecretGuard` iterate `SecretVault#each_plaintext` (only
  previously-resolved secrets).
- No category restriction on `by_name` / `by_tag`; no binding between the item
  and the page it is typed into.

## Design decisions (resolved)

1. **Eager reveal on discovery.** A discovery tool fetches full detail
   (`--reveal`) for each item it _returns_ and encrypts all field values into
   the cache up front. Typing reads the cache.
2. **On-demand fetch on cache miss.** If `browser_type_secret` targets an item
   not in the cache, fetch that one item (LOGIN-only, `--reveal`), cache it,
   then proceed (still subject to the URL check).
3. **LOGIN-only, silent.** All discovery tools and the cache are restricted to
   `category == "LOGIN"`. A name/tag hit on a non-LOGIN item is treated as
   absent (no special error).
4. **URL binding via proxy-injected `browser_evaluate`.** At type time the
   proxy makes its own internal upstream call to read `location.href`; the
   caller never supplies the URL. If it cannot be determined, typing is refused
   (fail closed).
5. **Match rule: host + path prefix.** Typing is allowed iff the item has at
   least one URL `u` such that `same_site?(host(u), page_host)` **and** the
   page path is covered by `u`'s path — i.e. `u`'s path is root/empty, equals
   the page path, or is a `"<path>/"` prefix of it. This is the boolean
   `matched` condition already inside `WebsiteMatcher#path_score`; it must be
   exposed as its own predicate rather than inferred from the numeric score
   (score `0` is ambiguous — it means both "root path, matches" and
   "non-prefix, no match").
6. **Discovery tools reshaped.** The tool set becomes:
   - `browser_list_items` — all LOGIN items valid for the current browser page.
   - `browser_find_items_by_name` — name search, results filtered to the
     current page.
   - `browser_find_items_by_tag` — tag search, results filtered to the current
     page.

   There is no dedicated clear tool: the cache is emptied when the client
   closes the browser via the upstream `browser_close` tool (see decision 8).

   The old `browser_find_secret_by_*` names are gone; `by_url` is dropped
   entirely — matching the current page URL is now the baseline filter on every
   discovery tool, not a separate tool. The three read tools return the found
   **items without any field values** — identity (vault/item/title/urls/tags)
   plus field metadata (labels, purposes, section labels) — so the LLM can pick
   one item and the right field. The typing tool keeps the name
   `browser_type_secret`.
7. **Discovery is current-URL scoped.** Every read discovery tool reads the
   current `location.href` (same proxy-injected `browser_evaluate` as typing)
   and returns only items whose URL set matches it under the same host +
   path-prefix rule (decision 5). If the current URL cannot be determined,
   discovery fails closed with an error.
8. **Write-once cache, cleared on `browser_close`.** A discovered item is
   cached once and not refreshed by later discovery (decision-4 flow). When the
   client calls the upstream `browser_close` tool, the proxy first removes
   **all cached items and their encrypted field values** — so their plaintext
   can no longer be decrypted or surfaced — and then forwards the close to the
   upstream server unchanged. The service-account token (a loose secret needed
   for continued `op` access) is **not** cleared. There is no dedicated clear
   tool.

## Data model

```crystal
record ItemKey, vault_id : String, item_id : String   # value equality + hash

record Item,
  key      : ItemKey,
  title    : String,
  urls     : Array(String),            # the URL set
  tags     : Array(String),            # non-secret metadata
  fields   : Hash(String, Field),      # field_id  => Field
  sections : Hash(String, Section)     # section_id => Section

record Field,
  id         : String,
  section_id : String?,                # nil when not in a section
  type       : String,                 # e.g. "CONCEALED", "STRING"
  purpose    : String?,                # "USERNAME" | "PASSWORD" | ... | nil
  label      : String,
  value      : EncryptedSecret?        # encrypted; nil when the field has no value

record Section, id : String, label : String
```

- Only `Field#value` is encrypted (via the existing cipher). All other
  properties are non-secret metadata stored plaintext. Valueless fields hold
  `nil`.
- `Item` replaces the old lightweight identity record. `WebsiteMatcher` and
  `ItemResult` operate on it and expose only identity/URLs/tags/field-metadata
  to the LLM — never a value.

## ItemCache

Replaces `SecretVault` (`secret_vault.cr` → `item_cache.cr`).

- `store(item : Item)` — insert by `item.key`; no-op / keep existing if already
  present (write-once).
- `fetch(key : ItemKey) : Item?`.
- `clear : Nil` — drop all cached items (and their encrypted values). Loose
  secrets (the token) are retained.
- `each_plaintext(& : String ->)` — collect every present `Field#value` across
  all items **plus** loose secrets, run one `cipher.decrypt_batch` (preserves
  the single Secure-Enclave key-unwrap on the redaction hot path), yield each.
- Loose-secret store for the `--token-tag` service-account token (not an item),
  so `Redactor`/`SecretGuard` still cover it.
- The old `SHA256(ref) → EncryptedSecret` API is retired.

## Flows

### Discovery (`browser_list_items` / `browser_find_items_by_name` / `_by_tag`)

1. **Read current page URL** via the proxy-injected `browser_evaluate`
   (`location.href`). If unavailable → fail closed with an error.
2. `ItemLocator` lists candidates restricted to `--categories Login` (plus
   `--tags` and/or vault scope as applicable to the tool; `browser_list_items`
   applies no name/tag filter).
3. Filter candidates to those whose URL set matches the current page under
   `WebsiteMatcher` (host + path-prefix), ordered most-specific first. Matching
   uses the URLs already present in `op item list` output, so no reveal is
   needed to filter.
4. Collect the survivors **not already cached** and reveal them in a **single
   batched `op` call**: pipe their specifiers as a JSON array into
   `op item get - --reveal --format=json` (the `-` form reads object specifiers
   from stdin and returns one item per object with an `id` key). Build an
   `Item` per returned object (encrypting each field value) and store it.
   Already-cached survivors are reused as-is — re-discovery does **not**
   refresh or re-reveal them (the cache is write-once per item until explicitly
   cleared). If no survivor needs loading, no reveal call is made.
5. `ItemResult` returns the surviving items — identity
   (vault/item/title/urls/tags) plus field metadata (labels/purposes/sections);
   **never values** — for the LLM to pick one.

### Typing (`browser_type_secret`)

Arguments unchanged: `element`, `ref`, `vault`, `item`, `field`, `submit?`,
`slowly?`.

1. Look up `ItemKey(vault, item)` in the cache. Miss → on-demand reveal that
   one item (LOGIN-only) via the same batched reveal path with a single
   specifier; if it does not exist or is not LOGIN → error.
2. **URL binding (fail closed):** proxy issues an internal injected
   `browser_evaluate` to read `location.href`. If it cannot be determined →
   refuse.
3. `WebsiteMatcher#matches?(page_url, item)` (host + path-prefix). No match →
   refuse: "current page `<the-url>` is not in this item's URL set". Checked
   _before_ any value is decrypted.
4. `FieldSelector` resolves `field` against the cached item: preference
   `purpose` (`USERNAME`/`PASSWORD`) → `label == field` → `id == field`,
   preferring a field that has a value; decrypt it.
5. Inject upstream `browser_type` (`element`, `target = ref`,
   `text =
   decrypted`, `submit?`, `slowly?`); redact the response; return.

The internal `browser_evaluate` is a proxy-initiated injected call with its own
id; it is unaffected by any future policy that blocks the _LLM_ from calling
`browser_evaluate` directly (security-review finding H1 — complementary, out of
scope here).

## Module changes

- `secret_vault.cr` → `item_cache.cr` (`ItemCache`).
- `item.cr`: `ItemKey`, `Item`, `Field`, `Section` records.
- `item_locator.cr`: keep the LOGIN-scoped list/by-tag helpers (summary only,
  no reveal — used for URL filtering). Add a **batched reveal**
  `reveal_items(specifiers) : Array(Item)` that pipes a JSON array of
  `{id, vault}` specifiers to `op item get - --reveal --format=json` (via
  `OpRunner`'s `input:` stdin) and parses the returned array into `Item`s;
  enforce LOGIN. The on-demand type path calls it with a single specifier.
- `secret_resolver.cr`: **retired**. Field-preference ranking moves to a new
  `FieldSelector`; account/service-account-token env handling already lives in
  `ItemLocator`.
- `secret_finders.cr`: replace the finders with `browser_list_items`,
  `browser_find_items_by_name`, `browser_find_items_by_tag` (drop the URL
  finder); update `NAME`s and `definition`s; each takes the current page URL,
  filters candidates via `WebsiteMatcher`, reveals + caches uncached survivors,
  returns `Item`s. LOGIN-only.
- Cache clearing: `proxy.cr` calls `ItemCache#clear` when the client invokes
  the upstream `browser_close` tool, before forwarding the close; no dedicated
  tool class.
- `proxy.cr` `INSTRUCTIONS`: rewrite the guidance string for the new tool names
  and the current-page-scoped behavior.
- New `PageUrl` reader: encapsulates the proxy-injected `browser_evaluate`
  `location.href` call; shared by discovery and typing. Fail-closed when the
  URL is unavailable.
- `secret_type_tool.cr`: resolve field from the cached `Item` via
  `FieldSelector`, decrypt, build upstream args.
- `website_matcher.cr`: operate on `Item`; add
  `matches?(page_url, item) : Bool` (host + path-prefix predicate, not
  score-based) for discovery filtering and the type-time check; keep
  specificity ordering for discovery results.
- `proxy.cr`: dispatch the three read discovery tools and
  `browser_type_secret`; clear the item cache on `browser_close` before
  forwarding it; `handle_secret_call` → cache lookup + on-demand fetch + URL
  binding (via `PageUrl`) + field resolution; discovery handlers read
  `PageUrl`, filter, and reveal uncached survivors.
- `item_result.cr`: include field metadata (+ tags) in output.
- `application.cr`: drop `SecretResolver` wiring; store the token as a loose
  secret in `ItemCache`.

## Testing

Unit:

- `item_cache`: store/fetch, write-once (second `store` of same key keeps the
  first), `clear` removes items but retains loose secrets, `each_plaintext`
  over field values + loose secrets, ciphertext-only introspection guarantee.
- `item_locator`: LOGIN-scoped list/by-tag (summary); batched `reveal_items`
  reads the JSON array from stdin and parses multiple items in one call; LOGIN
  filter; single-specifier reveal for the on-demand path — via `fake_op`
  fixtures that echo the piped stdin.
- `website_matcher#matches?`: host match, subdomain, path-prefix accept, path
  mismatch reject, bare-domain items.
- `secret_type_tool` / `FieldSelector`: purpose vs label vs id resolution,
  valueless-field skip, missing field error.
- `redactor` / `secret_guard`: cover every cached field value and the loose
  token.
- `PageUrl`: parses `location.href` from a fake upstream `evaluate` reply;
  errors when unavailable.
- discovery finders: current-URL filtering keeps matching items and drops
  non-matching / non-LOGIN ones; `browser_list_items` returns all current-page
  matches; `by_name` / `by_tag` narrow within them; re-discovery does not
  re-reveal an already-cached item; a client `browser_close` call empties the
  cache and is still forwarded upstream.
- `proxy`: discovery scoped to current page; URL-binding allow and refuse on
  type; on-demand fetch on cache miss; fail-closed when `location.href` is
  unavailable — against a fake upstream that answers the injected `evaluate`.

Integration: `browser_list_items` returns only current-page items; off-domain
type refused; on-domain type succeeds; non-LOGIN item filtered from discovery.

## Out of scope

- Blocking the LLM from calling `browser_evaluate` / `browser_run_code_unsafe`
  / screenshots (finding H1).
- `mlock`/zeroed plaintext buffers and per-message full-vault decryption cost
  (findings M1/M3).
- Redactor encoding-variant gaps (findings M4/M5).
