# Item cache + LOGIN scope + URL-bound typing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the flat secret vault with a structured, per-item cache
(`{vault_id, item_id}` → item with encrypted field values), restrict all
1Password access to category LOGIN, scope discovery to the current browser
page, and only type a secret into a page whose URL is in the item's URL set.

**Architecture:** Discovery tools list LOGIN candidates (summary), filter them
to the current page URL via `WebsiteMatcher`, batch-reveal the uncached
survivors in a single `op item get - --reveal` call, and cache full `Item`
objects with per-field encrypted values. `browser_type_secret` reads the cache
(fetching one item on demand if missing), re-checks the page URL, resolves the
field, and injects an upstream `browser_type`. The redactor/guard cover every
cached field value plus the loose service-account token.

**Tech Stack:** Crystal ≥ 1.20, Spectator specs, the `op` 1Password CLI (faked
in specs via bash fixtures), MCP JSON-RPC 2.0 over stdio.

## Global Constraints

- Crystal `>= 1.20`; object-oriented style per `my:development-crystal`
  (instance methods over class methods; navigate with Serena but **edit with
  Edit/Write** — Serena `replace_symbol` corrupts Crystal).
- A resolved secret value MUST NOT reach the client except redacted, MUST NOT
  be logged unredacted, and MUST NOT be passed on any command line (only via
  stdin or process env).
- `op` is invoked only through `OpRunner.run` (hard timeout, force-kill).
- Discovery and typing read the current page URL only from the proxy-injected
  `browser_evaluate`; the caller never supplies it.
- LOGIN-only: every `op` item access filters/verifies `category == "LOGIN"`.
- Field values are the only encrypted data; all other item metadata is
  plaintext.
- Run `rake spec` and `rake lint` before every commit; both must pass.
- Commit messages: plain, human, no AI/Claude/Copilot references. Do not commit
  unless the human has authorized it for this work.

---

## File structure

- `src/playwright_secure_mcp/item.cr` — `ItemKey`, `Item`, `Field`, `Section`
  records (replaces the old identity `Item`).
- `src/playwright_secure_mcp/item_cache.cr` — `ItemCache` (replaces
  `secret_vault.cr`).
- `src/playwright_secure_mcp/website_matcher.cr` — operate on `Item`; add
  `matches?`.
- `src/playwright_secure_mcp/item_locator.cr` — LOGIN list/by-tag (summary) +
  batched `reveal_items`.
- `src/playwright_secure_mcp/field_selector.cr` — resolve a field within an
  `Item`.
- `src/playwright_secure_mcp/item_finders.cr` — the three read discovery tools
  (replaces `secret_finders.cr`).
- `src/playwright_secure_mcp/clear_items_tool.cr` — `browser_clear_items`.
- `src/playwright_secure_mcp/page_url.cr` — reads `location.href` via an
  injected upstream call.
- `src/playwright_secure_mcp/secret_type_tool.cr` — resolve field from cache,
  build upstream args.
- `src/playwright_secure_mcp/item_result.cr` — serialize identity + field
  metadata.
- `src/playwright_secure_mcp/proxy.cr` — dispatch + URL binding + on-demand
  fetch.
- `src/playwright_secure_mcp/application.cr` — wiring.
- Delete: `src/playwright_secure_mcp/secret_resolver.cr`,
  `src/playwright_secure_mcp/secret_vault.cr`,
  `src/playwright_secure_mcp/secret_finders.cr`.
- Update requires in `src/playwright_secure_mcp.cr`.

---

### Task 1: Data model — `ItemKey`, `Item`, `Field`, `Section`

**Files:**

- Modify (replace contents): `src/playwright_secure_mcp/item.cr`
- Test: `spec/item_spec.cr` (create)

**Interfaces:**

- Produces:
  - `record ItemKey, vault_id : String, item_id : String`
  - `record Item, key : ItemKey, title : String, urls : Array(String), tags : Array(String), fields : Hash(String, Field), sections : Hash(String, Section)`
  - `record Field, id : String, section_id : String?, type : String, purpose : String?, label : String, value : EncryptedSecret?`
  - `record Section, id : String, label : String`
  - `Item#vault_id : String` and `Item#item_id : String` convenience
    delegators.

- [ ] **Step 1: Write the failing test**

```crystal
# spec/item_spec.cr
require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::Item do
  it "exposes vault and item ids via its key" do
    key = PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "i1")
    item = PlaywrightSecureMcp::Item.new(
      key: key, title: "T", urls: ["https://x"], tags: ["a"],
      fields: {} of String => PlaywrightSecureMcp::Field,
      sections: {} of String => PlaywrightSecureMcp::Section,
    )
    expect(item.vault_id).to eq("v1")
    expect(item.item_id).to eq("i1")
  end

  it "uses value equality for keys (usable as a hash key)" do
    a = PlaywrightSecureMcp::ItemKey.new(vault_id: "v", item_id: "i")
    b = PlaywrightSecureMcp::ItemKey.new(vault_id: "v", item_id: "i")
    cache = {a => 1}
    expect(cache[b]?).to eq(1)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `crystal spec spec/item_spec.cr` Expected: FAIL (constructor/records not
matching; `Item.new` signature changed).

- [ ] **Step 3: Replace `src/playwright_secure_mcp/item.cr`**

```crystal
require "./encrypted_secret"

module PlaywrightSecureMcp
  # Identity of a cached 1Password item: the {vault, item} pair. A record, so it
  # has value equality and hashing and can key the cache.
  record ItemKey, vault_id : String, item_id : String

  # A section of a 1Password item (groups custom fields).
  record Section, id : String, label : String

  # A single field of a 1Password item. Only `value` is a secret; it is stored
  # encrypted, and is nil for fields that have no value.
  record Field,
    id : String,
    section_id : String?,
    type : String,
    purpose : String?,
    label : String,
    value : EncryptedSecret?

  # A cached 1Password LOGIN item. Carries only non-secret metadata in the clear;
  # each field's secret value is encrypted inside `Field#value`.
  record Item,
    key : ItemKey,
    title : String,
    urls : Array(String),
    tags : Array(String),
    fields : Hash(String, Field),
    sections : Hash(String, Section) do
    def vault_id : String
      key.vault_id
    end

    def item_id : String
      key.item_id
    end
  end
end
```

- [ ] **Step 4: Run test to verify it passes**

Run: `crystal spec spec/item_spec.cr` Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add spec/item_spec.cr src/playwright_secure_mcp/item.cr
git commit -m "Introduce structured Item/Field/Section/ItemKey records"
```

---

### Task 2: `ItemCache` (replaces `SecretVault`)

**Files:**

- Create: `src/playwright_secure_mcp/item_cache.cr`
- Delete: `src/playwright_secure_mcp/secret_vault.cr`
- Test: `spec/item_cache_spec.cr` (create); delete `spec/secret_vault_spec.cr`

**Interfaces:**

- Consumes: `Item`, `ItemKey`, `Field` (Task 1); `SecretCipher`,
  `InMemoryCipher`, `EncryptedSecret` (existing).
- Produces:
  - `ItemCache.new(cipher : SecretCipher = InMemoryCipher.new)`
  - `#encrypt(plaintext : String) : EncryptedSecret` — helper so callers build
    `Field#value` with the cache's cipher.
  - `#decrypt(entry : EncryptedSecret) : String` — decrypt a field value at
    type time (used by the proxy).
  - `#store(item : Item) : Nil` — write-once (ignored if key present).
  - `#fetch(key : ItemKey) : Item?`
  - `#has?(key : ItemKey) : Bool`
  - `#clear : Nil` — drops all items; keeps loose secrets.
  - `#add_loose_secret(secret : String) : Nil`
  - `#each_plaintext(& : String ->) : Nil` — every present field value across
    all items plus loose secrets, one `decrypt_batch`.
  - `#each_ciphertext_for_test(& : Bytes ->) : Nil`

- [ ] **Step 1: Write the failing test**

```crystal
# spec/item_cache_spec.cr
require "./spec_helper"

private def field(cache, label, value)
  PlaywrightSecureMcp::Field.new(
    id: label, section_id: nil, type: "STRING", purpose: nil,
    label: label, value: value.nil? ? nil : cache.encrypt(value))
end

private def item(cache, vault, id, fields)
  PlaywrightSecureMcp::Item.new(
    key: PlaywrightSecureMcp::ItemKey.new(vault_id: vault, item_id: id),
    title: id, urls: [] of String, tags: [] of String,
    fields: fields, sections: {} of String => PlaywrightSecureMcp::Section)
end

Spectator.describe PlaywrightSecureMcp::ItemCache do
  let(cache) { PlaywrightSecureMcp::ItemCache.new }
  let(key) { PlaywrightSecureMcp::ItemKey.new(vault_id: "v", item_id: "i") }

  it "stores and fetches an item" do
    cache.store(item(cache, "v", "i", {"password" => field(cache, "password", "pw")}))
    fetched = cache.fetch(key)
    expect(fetched.try(&.item_id)).to eq("i")
  end

  it "is write-once: a second store of the same key is ignored" do
    cache.store(item(cache, "v", "i", {"password" => field(cache, "password", "first")}))
    cache.store(item(cache, "v", "i", {"password" => field(cache, "password", "second")}))
    values = [] of String
    cache.each_plaintext { |s| values << s }
    expect(values).to eq(["first"])
  end

  it "yields every present field value plus loose secrets" do
    cache.store(item(cache, "v", "i", {
      "u" => field(cache, "username", "alice"),
      "p" => field(cache, "password", "pw"),
      "e" => field(cache, "empty", nil),
    }))
    cache.add_loose_secret("tok")
    got = [] of String
    cache.each_plaintext { |s| got << s }
    expect(got.sort).to eq(["alice", "pw", "tok"])
  end

  it "clear drops items but keeps loose secrets" do
    cache.store(item(cache, "v", "i", {"p" => field(cache, "password", "pw")}))
    cache.add_loose_secret("tok")
    cache.clear
    expect(cache.fetch(key)).to be_nil
    got = [] of String
    cache.each_plaintext { |s| got << s }
    expect(got).to eq(["tok"])
  end

  it "keeps neither plaintext nor label in ciphertext" do
    cache.store(item(cache, "v", "i", {"p" => field(cache, "password", "super-secret")}))
    dumped = [] of String
    cache.each_ciphertext_for_test { |b| dumped << b.hexstring }
    expect(dumped.join.includes?("super-secret".to_slice.hexstring)).to be_false
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `crystal spec spec/item_cache_spec.cr` Expected: FAIL (`ItemCache`
undefined).

- [ ] **Step 3: Create `src/playwright_secure_mcp/item_cache.cr` and delete
      `secret_vault.cr`**

```crystal
require "./item"
require "./encrypted_secret"
require "./secret_cipher"
require "./in_memory_cipher"

module PlaywrightSecureMcp
  # In-memory cache of revealed LOGIN items. Field values are encrypted at rest
  # under the process cipher; all other item metadata is kept in the clear.
  # Write-once per key: a re-discovered item is not refreshed until `clear`.
  class ItemCache
    def initialize(@cipher : SecretCipher = InMemoryCipher.new)
      @items = {} of ItemKey => Item
      @loose = [] of EncryptedSecret
    end

    def encrypt(plaintext : String) : EncryptedSecret
      @cipher.encrypt(plaintext.to_slice)
    end

    def store(item : Item) : Nil
      @items[item.key] ||= item
    end

    def fetch(key : ItemKey) : Item?
      @items[key]?
    end

    def has?(key : ItemKey) : Bool
      @items.has_key?(key)
    end

    def clear : Nil
      @items.clear
    end

    # Store a secret that is not part of an item (the service-account token), so
    # the redactor and guard cover it too.
    def add_loose_secret(secret : String) : Nil
      @loose << @cipher.encrypt(secret.to_slice)
    end

    def each_plaintext(& : String ->) : Nil
      entries = collect_entries
      return if entries.empty?
      @cipher.decrypt_batch(entries).each { |bytes| yield String.new(bytes) }
    end

    def each_ciphertext_for_test(& : Bytes ->) : Nil
      collect_entries.each { |entry| yield entry.ciphertext }
    end

    private def collect_entries : Array(EncryptedSecret)
      entries = [] of EncryptedSecret
      @items.each_value do |item|
        item.fields.each_value do |field|
          value = field.value
          entries << value unless value.nil?
        end
      end
      entries.concat(@loose)
      entries
    end
  end
end
```

Then:
`git rm src/playwright_secure_mcp/secret_vault.cr spec/secret_vault_spec.cr`

- [ ] **Step 4: Run test to verify it passes**

Run: `crystal spec spec/item_cache_spec.cr` Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add ItemCache with per-item encrypted field values, replacing SecretVault"
```

---

### Task 3: `WebsiteMatcher#matches?` + operate on `Item`

**Files:**

- Modify: `src/playwright_secure_mcp/website_matcher.cr`
- Test: `spec/website_matcher_spec.cr` (extend)

**Interfaces:**

- Consumes: `Item` (Task 1).
- Produces:
  - `#rank(page_url : String, items : Array(Item)) : Array(Item)` (unchanged
    signature; now on the new `Item`).
  - `#matches?(page_url : String, item : Item) : Bool` — true iff some item URL
    host-matches the page and its path is root/equal/prefix of the page path.

The existing `rank`/`best_match`/`path_score` already compute this; expose the
boolean cleanly. `path_score` returns `0` for both "root path (match)" and
"non-prefix (no match)", so `matches?` MUST test the boolean condition, not the
score.

- [ ] **Step 1: Write the failing test**

```crystal
# append to spec/website_matcher_spec.cr, inside the existing describe block
it "matches? is true for same host and prefix path, false otherwise" do
  matcher = PlaywrightSecureMcp::WebsiteMatcher.new
  item = PlaywrightSecureMcp::Item.new(
    key: PlaywrightSecureMcp::ItemKey.new(vault_id: "v", item_id: "i"),
    title: "t", urls: ["https://example.com/app"], tags: [] of String,
    fields: {} of String => PlaywrightSecureMcp::Field,
    sections: {} of String => PlaywrightSecureMcp::Section)
  expect(matcher.matches?("https://example.com/app/login", item)).to be_true
  expect(matcher.matches?("https://example.com/other", item)).to be_false
  expect(matcher.matches?("https://evil.com/app", item)).to be_false
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `crystal spec spec/website_matcher_spec.cr` Expected: FAIL (`matches?`
undefined; and existing specs may need the `Item` constructor updated — update
any `Item.new(...)` in this spec to the Task-1 shape as part of this step).

- [ ] **Step 3: Add `matches?` and split the path predicate**

In `website_matcher.cr`, change `path_score` to delegate to a boolean, and add
`matches?`:

```crystal
def matches?(page_url : String, item : Item) : Bool
  page = parse_url(page_url)
  return false if page.nil?
  page_host = normalize_host(page.host)
  page_path = page.path
  item.urls.any? do |raw|
    candidate = parse_url(raw)
    next false if candidate.nil?
    next false unless same_site?(normalize_host(candidate.host), page_host)
    path_matches?(candidate.path, page_path)
  end
end

# Root/empty item paths match every page path; otherwise require an exact match
# or a segment-boundary prefix.
private def path_matches?(item_path : String, page_path : String) : Bool
  return true if item_path.empty? || item_path == "/"
  page_path == item_path || page_path.starts_with?("#{item_path}/")
end

private def path_score(item_path : String, page_path : String) : Int32
  path_matches?(item_path, page_path) ? item_path.size : 0
end
```

(Keep `rank`, `best_match`, `same_site?`, `normalize_host`, `parse_url`,
`prioritize_url`; they now consume the new `Item`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `crystal spec spec/website_matcher_spec.cr` Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/playwright_secure_mcp/website_matcher.cr spec/website_matcher_spec.cr
git commit -m "Add WebsiteMatcher#matches? and operate on the new Item record"
```

---

### Task 4: `ItemLocator` — LOGIN list/by-tag + batched reveal

**Files:**

- Modify (rewrite): `src/playwright_secure_mcp/item_locator.cr`
- Test: `spec/item_locator_spec.cr` (rewrite)
- Test fixture: `spec/support/fake_op_items` (create, chmod +x)

**Interfaces:**

- Consumes: `Item`, `ItemKey`, `Field`, `Section` (Task 1); `ItemCache#encrypt`
  (Task 2) — passed in so revealed values are encrypted under the cache cipher;
  `OpRunner` (existing, supports `input:` stdin).
- Produces (all LOGIN-scoped):
  - `ItemLocator.new(*, op_command : String, account : String?, service_account_token : String? = nil, encryptor : ItemCache)`
  - `#list_logins(vault : String?) : Array(Item)` — summary items (urls/tags,
    empty fields/sections) for URL filtering.
  - `#list_by_tag(tag : String, vault : String?) : Array(Item)` — summary
    items.
  - `#reveal(keys : Array(ItemKey)) : Array(Item)` — one batched
    `op item get - --reveal --format=json`; returns full items with encrypted
    field values; drops any whose category ≠ LOGIN.

Summary items use `fields`/`sections` empty; `reveal` produces the full
objects.

- [ ] **Step 1: Write the failing test + fixture**

Fixture `spec/support/fake_op_items` (bash; remember Alpine has no bash on CI —
these run on the dev/macOS host, matching existing fixtures):

```bash
#!/usr/bin/env bash
# Fake `op` for ItemLocator reveal/list specs.
#   op item list --categories Login [--vault V] --format=json
#   op item get - --reveal --format=json   (specifiers as JSON array on stdin)
sub="$2"
category=""
for ((i=1;i<=$#;i++)); do
  [ "${!i}" = "--categories" ] && { j=$((i+1)); category="${!j}"; }
done

if [ "$1" = "item" ] && [ "$sub" = "list" ] && [ "$category" = "Login" ]; then
  printf '[{"id":"login1","title":"Example","category":"LOGIN","vault":{"id":"v1"},"urls":[{"href":"https://example.com/login"}],"tags":["work"]}]\n'
  exit 0
fi

if [ "$1" = "item" ] && [ "$sub" = "get" ] && [ "$3" = "-" ]; then
  input="$(cat)"
  # Return one login item (full, revealed) plus one non-login that must be dropped.
  printf '[{"id":"login1","title":"Example","category":"LOGIN","vault":{"id":"v1"},"urls":[{"href":"https://example.com/login"}],"tags":["work"],"sections":[{"id":"sec1","label":"More"}],"fields":[{"id":"username","type":"STRING","purpose":"USERNAME","label":"username","value":"alice"},{"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"pw"},{"id":"custom","type":"STRING","label":"Token","section":{"id":"sec1"},"value":"k"}]},{"id":"note1","title":"Note","category":"SECURE_NOTE","vault":{"id":"v1"},"fields":[]}]\n'
  exit 0
fi
exit 1
```

Test `spec/item_locator_spec.cr`:

```crystal
require "./spec_helper"

private FAKE_OP_ITEMS = File.expand_path("support/fake_op_items", __DIR__)

Spectator.describe PlaywrightSecureMcp::ItemLocator do
  let(cache) { PlaywrightSecureMcp::ItemCache.new }
  let(locator) do
    PlaywrightSecureMcp::ItemLocator.new(
      op_command: FAKE_OP_ITEMS, account: nil, encryptor: cache)
  end

  it "lists login items as summaries with urls and tags" do
    items = locator.list_logins(nil)
    expect(items.map(&.item_id)).to eq(["login1"])
    expect(items.first.urls).to eq(["https://example.com/login"])
    expect(items.first.tags).to eq(["work"])
    expect(items.first.fields.empty?).to be_true
  end

  it "reveals items in one batched call and encrypts field values" do
    keys = [PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1")]
    items = locator.reveal(keys)
    expect(items.map(&.item_id)).to eq(["login1"]) # non-login dropped
    fields = items.first.fields
    expect(fields.size).to eq(3)
    pw = fields.values.find { |f| f.purpose == "PASSWORD" }.not_nil!
    expect(pw.value).not_to be_nil
    # value is encrypted, not the plaintext
    expect(String.new(pw.value.not_nil!.ciphertext)).not_to eq("pw")
  end

  it "maps sections onto the item" do
    items = locator.reveal([PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1")])
    expect(items.first.sections["sec1"].label).to eq("More")
    custom = items.first.fields["custom"]
    expect(custom.section_id).to eq("sec1")
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run:
`chmod +x spec/support/fake_op_items && crystal spec spec/item_locator_spec.cr`
Expected: FAIL (new `ItemLocator` API undefined).

- [ ] **Step 3: Rewrite `src/playwright_secure_mcp/item_locator.cr`**

```crystal
require "json"
require "./item"
require "./item_cache"
require "./op_runner"

module PlaywrightSecureMcp
  # Looks up LOGIN items via the `op` CLI. Listing returns non-secret summaries
  # (no `--reveal`); `reveal` batch-fetches full items with their (encrypted)
  # field values. All results are restricted to category LOGIN.
  class ItemLocator
    class Error < Exception
    end

    LOGIN_CATEGORY = "LOGIN"

    def initialize(*, @op_command : String, @account : String?,
                   @service_account_token : String? = nil, @encryptor : ItemCache)
    end

    def list_logins(vault : String?) : Array(Item)
      output = run(["item", "list", "--categories", "Login", "--format=json"], vault: vault)
      summaries(output)
    end

    def list_by_tag(tag : String, vault : String?) : Array(Item)
      output = run(["item", "list", "--categories", "Login", "--tags", tag, "--format=json"], vault: vault)
      summaries(output)
    end

    # One batched `op item get - --reveal`: specifiers piped as a JSON array on
    # stdin. Returns full items; silently drops any whose category != LOGIN.
    def reveal(keys : Array(ItemKey)) : Array(Item)
      return [] of Item if keys.empty?
      specifiers = keys.map { |k| {"id" => k.item_id, "vault" => {"id" => k.vault_id}} }.to_json
      output = run(["item", "get", "-", "--reveal", "--format=json"], vault: nil, input: specifiers)
      parse_full(output)
    end

    private def summaries(output : String) : Array(Item)
      parse(output).map { |entry| summary_from(entry) }
    rescue error : TypeCastError
      raise Error.new("op returned a malformed item list: #{error.message}")
    end

    private def parse_full(output : String) : Array(Item)
      parse(output).compact_map do |entry|
        next nil unless entry["category"]?.try(&.as_s?) == LOGIN_CATEGORY
        full_from(entry)
      end
    rescue error : TypeCastError
      raise Error.new("op returned a malformed item: #{error.message}")
    end

    # `op item get -` returns a single object for one specifier, an array for
    # several; normalize to an array.
    private def parse(output : String) : Array(JSON::Any)
      parsed = JSON.parse(output)
      parsed.as_a? || [parsed]
    end

    private def summary_from(entry : JSON::Any) : Item
      Item.new(
        key: key_of(entry),
        title: entry["title"]?.try(&.as_s) || "",
        urls: urls_of(entry),
        tags: tags_of(entry),
        fields: {} of String => Field,
        sections: {} of String => Section)
    rescue error : KeyError | TypeCastError | NilAssertionError
      raise Error.new("op returned a malformed item: #{error.message}")
    end

    private def full_from(entry : JSON::Any) : Item
      sections = {} of String => Section
      (entry["sections"]?.try(&.as_a) || [] of JSON::Any).each do |raw|
        id = raw["id"]?.try(&.as_s)
        next if id.nil?
        sections[id] = Section.new(id: id, label: raw["label"]?.try(&.as_s) || "")
      end

      fields = {} of String => Field
      (entry["fields"]?.try(&.as_a) || [] of JSON::Any).each do |raw|
        id = raw["id"]?.try(&.as_s)
        next if id.nil?
        raw_value = raw["value"]?.try(&.as_s)
        fields[id] = Field.new(
          id: id,
          section_id: raw.dig?("section", "id").try(&.as_s),
          type: raw["type"]?.try(&.as_s) || "",
          purpose: raw["purpose"]?.try(&.as_s),
          label: raw["label"]?.try(&.as_s) || "",
          value: (raw_value && !raw_value.empty?) ? @encryptor.encrypt(raw_value) : nil)
      end

      Item.new(key: key_of(entry), title: entry["title"]?.try(&.as_s) || "",
        urls: urls_of(entry), tags: tags_of(entry), fields: fields, sections: sections)
    rescue error : KeyError | TypeCastError | NilAssertionError
      raise Error.new("op returned a malformed item: #{error.message}")
    end

    private def key_of(entry : JSON::Any) : ItemKey
      ItemKey.new(vault_id: entry["vault"]["id"].as_s, item_id: entry["id"].as_s)
    end

    private def urls_of(entry : JSON::Any) : Array(String)
      entry["urls"]?.try(&.as_a.compact_map(&.["href"]?.try(&.as_s))) || [] of String
    end

    private def tags_of(entry : JSON::Any) : Array(String)
      entry["tags"]?.try(&.as_a.compact_map(&.as_s?)) || [] of String
    end

    private def run(arguments : Array(String), *, vault : String?, input : String? = nil) : String
      argv = arguments.dup
      argv << "--vault" << vault if vault
      if token = @service_account_token
        env = {"OP_SERVICE_ACCOUNT_TOKEN" => token.as(String?)}
      else
        env = nil
        argv << "--account" << @account.as(String) if @account
      end

      stdin = input ? IO::Memory.new(input) : Process::Redirect::Close
      output = IO::Memory.new
      status =
        begin
          OpRunner.run(@op_command, argv, env: env, input: stdin, output: output)
        rescue error : OpRunner::TimeoutError
          raise Error.new("op #{arguments.join(" ")} timed out: #{error.message}")
        end
      raise Error.new("op #{arguments.join(" ")} failed (exit #{status.exit_code? || "signal"})") unless status.success?

      output.to_s
    end
  end
end
```

- [ ] **Step 4: Run test to verify it passes**

Run: `crystal spec spec/item_locator_spec.cr` Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/playwright_secure_mcp/item_locator.cr spec/item_locator_spec.cr spec/support/fake_op_items
git commit -m "Rework ItemLocator for LOGIN summaries and batched reveal"
```

---

### Task 5: `FieldSelector`

**Files:**

- Create: `src/playwright_secure_mcp/field_selector.cr`
- Test: `spec/field_selector_spec.cr` (create)

**Interfaces:**

- Consumes: `Item`, `Field` (Task 1).
- Produces:
  - `FieldSelector::PURPOSES = {"username" => "USERNAME", "password" => "PASSWORD"}`
  - `FieldSelector.new`
  - `#select(item : Item, field : String) : Field` — preference: purpose match
    (for username/password) → `label == field` → `id == field`, preferring a
    field with a non-nil value. Raises `FieldSelector::NotFoundError` if none.
  - `class NotFoundError < Exception`

- [ ] **Step 1: Write the failing test**

```crystal
# spec/field_selector_spec.cr
require "./spec_helper"

private def fld(id, purpose, label, has_value)
  PlaywrightSecureMcp::Field.new(
    id: id, section_id: nil, type: "STRING", purpose: purpose, label: label,
    value: has_value ? PlaywrightSecureMcp::EncryptedSecret.new(iv: Bytes.new(0), ciphertext: Bytes.new(1)) : nil)
end

private def item_with(fields)
  PlaywrightSecureMcp::Item.new(
    key: PlaywrightSecureMcp::ItemKey.new(vault_id: "v", item_id: "i"),
    title: "t", urls: [] of String, tags: [] of String,
    fields: fields, sections: {} of String => PlaywrightSecureMcp::Section)
end

Spectator.describe PlaywrightSecureMcp::FieldSelector do
  let(selector) { PlaywrightSecureMcp::FieldSelector.new }

  it "selects by purpose for username/password" do
    item = item_with({
      "f1" => fld("f1", "PASSWORD", "Kennwort", true),
      "f2" => fld("f2", nil, "password", false),
    })
    expect(selector.select(item, "password").id).to eq("f1")
  end

  it "falls back to label then id" do
    item = item_with({"f1" => fld("f1", nil, "API Key", true)})
    expect(selector.select(item, "API Key").id).to eq("f1")
    expect(selector.select(item, "f1").id).to eq("f1")
  end

  it "raises when no field matches" do
    item = item_with({"f1" => fld("f1", nil, "x", true)})
    expect { selector.select(item, "nope") }.to raise_error(PlaywrightSecureMcp::FieldSelector::NotFoundError)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `crystal spec spec/field_selector_spec.cr` Expected: FAIL (`FieldSelector`
undefined).

- [ ] **Step 3: Create `src/playwright_secure_mcp/field_selector.cr`**

```crystal
require "./item"

module PlaywrightSecureMcp
  # Resolves a caller-supplied field name to a concrete Field within a cached
  # item, mirroring the old SecretResolver preference order.
  class FieldSelector
    class NotFoundError < Exception
    end

    PURPOSES = {"username" => "USERNAME", "password" => "PASSWORD"}

    def select(item : Item, field : String) : Field
      purpose = PURPOSES[field]?
      candidates = item.fields.each_value.select do |candidate|
        matches?(candidate, field: field, purpose: purpose)
      end.to_a
      best = candidates.max_by? { |candidate| rank(candidate, purpose: purpose) }
      raise NotFoundError.new("no field #{field.inspect} on item") if best.nil?
      best
    end

    private def matches?(field : Field, *, field name : String, purpose : String?) : Bool
      field.id == name || field.label == name ||
        (!purpose.nil? && field.purpose == purpose)
    end

    private def rank(field : Field, *, purpose : String?) : Tuple(Int32, Int32)
      purpose_match = !purpose.nil? && field.purpose == purpose
      {purpose_match ? 1 : 0, field.value.nil? ? 0 : 1}
    end
  end
end
```

Note: Crystal does not allow `field name : String` as an external/internal name
pair inside a method that already has a param called `field`. Rename the param
— use `def matches?(candidate : Field, *, name : String, purpose : String?)`
and update the call site accordingly:

```crystal
  candidates = item.fields.each_value.select do |candidate|
    matches?(candidate, name: field, purpose: purpose)
  end.to_a
  ...
private def matches?(candidate : Field, *, name : String, purpose : String?) : Bool
  candidate.id == name || candidate.label == name ||
    (!purpose.nil? && candidate.purpose == purpose)
end
```

- [ ] **Step 4: Run test to verify it passes**

Run: `crystal spec spec/field_selector_spec.cr` Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/playwright_secure_mcp/field_selector.cr spec/field_selector_spec.cr
git commit -m "Add FieldSelector for resolving a field within a cached item"
```

---

### Task 6: `PageUrl` reader

**Files:**

- Create: `src/playwright_secure_mcp/page_url.cr`
- Test: `spec/page_url_spec.cr` (create)

**Interfaces:**

- Consumes: nothing new; takes a caller-provided block that performs the
  upstream `tools/call` and returns the response `JSON::Any` (so it is
  unit-testable and decoupled from `Proxy`'s private `call_upstream`).
- Produces:
  - `class PageUrl::UnavailableError < Exception`
  - `PageUrl.new`
  - `#current(& : JSON::Any -> JSON::Any) : String` — builds the
    `browser_evaluate` arguments (`{"function" => "() => location.href"}`),
    yields them wrapped as a `tools/call` `params` object to the block,
    extracts the URL string from the result content, and raises
    `UnavailableError` if missing/blank.

- [ ] **Step 1: Write the failing test**

```crystal
# spec/page_url_spec.cr
require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::PageUrl do
  let(reader) { PlaywrightSecureMcp::PageUrl.new }

  private def result_with(text : String) : JSON::Any
    content = [JSON::Any.new({"type" => JSON::Any.new("text"), "text" => JSON::Any.new(text)})]
    JSON::Any.new({"result" => JSON::Any.new({"content" => JSON::Any.new(content)})})
  end

  it "asks upstream to evaluate location.href and returns the url" do
    seen = nil.as(JSON::Any?)
    url = reader.current do |params|
      seen = params
      result_with("https://example.com/login")
    end
    expect(url).to eq("https://example.com/login")
    expect(seen.not_nil!["name"].as_s).to eq("browser_evaluate")
  end

  it "raises when the url cannot be determined" do
    expect do
      reader.current { |_| result_with("   ") }
    end.to raise_error(PlaywrightSecureMcp::PageUrl::UnavailableError)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `crystal spec spec/page_url_spec.cr` Expected: FAIL (`PageUrl` undefined).

- [ ] **Step 3: Create `src/playwright_secure_mcp/page_url.cr`**

```crystal
require "json"

module PlaywrightSecureMcp
  # Reads the current page URL by asking the upstream server to evaluate
  # `location.href`. The actual upstream round-trip is supplied by the caller so
  # this stays decoupled from Proxy internals.
  class PageUrl
    class UnavailableError < Exception
    end

    EVALUATE_TOOL = "browser_evaluate"

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

    private def extract(response : JSON::Any) : String?
      return nil unless response["error"]?.nil?
      content = response.dig?("result", "content").try(&.as_a?)
      return nil if content.nil?
      text = content.compact_map { |part| part["text"]?.try(&.as_s?) }.first?
      text
    end
  end
end
```

- [ ] **Step 4: Run test to verify it passes**

Run: `crystal spec spec/page_url_spec.cr` Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/playwright_secure_mcp/page_url.cr spec/page_url_spec.cr
git commit -m "Add PageUrl reader for the injected location.href evaluate"
```

---

### Task 7: `ItemResult` — identity + field metadata

**Files:**

- Modify: `src/playwright_secure_mcp/item_result.cr`
- Test: `spec/item_result_spec.cr` (rewrite)

**Interfaces:**

- Consumes: `Item`, `Field`, `Section` (Task 1).
- Produces: `#build(items : Array(Item)) : JSON::Any` — MCP tool result whose
  text content is a JSON array of
  `{vault, item, title, urls, tags, fields:[{label,
  purpose, section}], sections:[...]}`.
  Never a value.

- [ ] **Step 1: Write the failing test**

```crystal
# spec/item_result_spec.cr
require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::ItemResult do
  it "serializes identity and field metadata but never values" do
    field = PlaywrightSecureMcp::Field.new(
      id: "password", section_id: nil, type: "CONCEALED", purpose: "PASSWORD",
      label: "password",
      value: PlaywrightSecureMcp::EncryptedSecret.new(iv: Bytes.new(0), ciphertext: "cipher".to_slice))
    item = PlaywrightSecureMcp::Item.new(
      key: PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "i1"),
      title: "Example", urls: ["https://example.com"], tags: ["work"],
      fields: {"password" => field}, sections: {} of String => PlaywrightSecureMcp::Section)

    result = PlaywrightSecureMcp::ItemResult.new.build([item])
    text = result["content"].as_a.first["text"].as_s
    expect(text.includes?("cipher")).to be_false
    payload = JSON.parse(text).as_a.first
    expect(payload["vault"].as_s).to eq("v1")
    expect(payload["item"].as_s).to eq("i1")
    expect(payload["fields"].as_a.first["label"].as_s).to eq("password")
    expect(payload["fields"].as_a.first["purpose"].as_s).to eq("PASSWORD")
    expect(result["isError"].as_bool).to be_false
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `crystal spec spec/item_result_spec.cr` Expected: FAIL (old `ItemResult`
uses the removed identity `Item`).

- [ ] **Step 3: Rewrite `src/playwright_secure_mcp/item_result.cr`**

```crystal
require "json"
require "./item"

module PlaywrightSecureMcp
  # Serializes discovery results into an MCP tool result: a JSON array of item
  # identities plus non-secret field metadata. Never includes a field value.
  class ItemResult
    def build(items : Array(Item)) : JSON::Any
      payload = JSON::Any.new(items.map { |item| candidate(item) }).to_json
      content = [JSON::Any.new({"type" => JSON::Any.new("text"), "text" => JSON::Any.new(payload)})]
      JSON::Any.new({"content" => JSON::Any.new(content), "isError" => JSON::Any.new(false)})
    end

    private def candidate(item : Item) : JSON::Any
      JSON::Any.new({
        "vault"    => JSON::Any.new(item.vault_id),
        "item"     => JSON::Any.new(item.item_id),
        "title"    => JSON::Any.new(item.title),
        "urls"     => JSON::Any.new(item.urls.map { |u| JSON::Any.new(u) }),
        "tags"     => JSON::Any.new(item.tags.map { |t| JSON::Any.new(t) }),
        "fields"   => JSON::Any.new(item.fields.values.map { |f| field(f) }),
        "sections" => JSON::Any.new(item.sections.values.map { |s| section(s) }),
      })
    end

    private def field(field : Field) : JSON::Any
      entry = {
        "label" => JSON::Any.new(field.label),
        "type"  => JSON::Any.new(field.type),
      } of String => JSON::Any
      purpose = field.purpose
      entry["purpose"] = JSON::Any.new(purpose) unless purpose.nil?
      section_id = field.section_id
      entry["section"] = JSON::Any.new(section_id) unless section_id.nil?
      JSON::Any.new(entry)
    end

    private def section(section : Section) : JSON::Any
      JSON::Any.new({"id" => JSON::Any.new(section.id), "label" => JSON::Any.new(section.label)})
    end
  end
end
```

- [ ] **Step 4: Run test to verify it passes**

Run: `crystal spec spec/item_result_spec.cr` Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/playwright_secure_mcp/item_result.cr spec/item_result_spec.cr
git commit -m "Serialize item identity plus field metadata in ItemResult"
```

---

### Task 8: `SecretTypeTool` — resolve field from cache

**Files:**

- Modify: `src/playwright_secure_mcp/secret_type_tool.cr`
- Test: `spec/secret_type_tool_spec.cr` (rewrite)

**Interfaces:**

- Consumes: `Item` (Task 1), `FieldSelector` (Task 5), `ItemCache` (decrypt via
  a cipher — but the tool receives the already-decrypted secret from the proxy
  to keep decryption in one place). Keep the tool responsible only for
  argument-shaping and field name extraction.
- Produces:
  - `SecretTypeTool::NAME = "browser_type_secret"`,
    `UPSTREAM_TOOL = "browser_type"`
  - `#definition : JSON::Any` (unchanged schema)
  - `#key(arguments : JSON::Any) : ItemKey` — from `vault`/`item`.
  - `#field_name(arguments : JSON::Any) : String` — from `field`.
  - `#build_browser_type_arguments(*, arguments : JSON::Any, secret : String) : JSON::Any`
    (unchanged behavior).
  - `class MissingArgumentError < Exception`

- [ ] **Step 1: Write the failing test**

```crystal
# spec/secret_type_tool_spec.cr
require "./spec_helper"

Spectator.describe PlaywrightSecureMcp::SecretTypeTool do
  let(tool) { PlaywrightSecureMcp::SecretTypeTool.new }

  private def args(hash) : JSON::Any
    JSON.parse(hash.to_json)
  end

  it "builds an ItemKey from vault and item" do
    key = tool.key(args({"vault" => "v1", "item" => "i1", "field" => "password"}))
    expect(key.vault_id).to eq("v1")
    expect(key.item_id).to eq("i1")
  end

  it "extracts the field name" do
    expect(tool.field_name(args({"vault" => "v", "item" => "i", "field" => "password"}))).to eq("password")
  end

  it "builds browser_type arguments with the secret and passes options through" do
    built = tool.build_browser_type_arguments(
      arguments: args({"element" => "Password", "ref" => "e1", "submit" => true}),
      secret: "s3cr3t")
    expect(built["target"].as_s).to eq("e1")
    expect(built["text"].as_s).to eq("s3cr3t")
    expect(built["submit"].as_bool).to be_true
  end

  it "raises when a required argument is missing" do
    expect { tool.key(args({"item" => "i", "field" => "password"})) }
      .to raise_error(PlaywrightSecureMcp::SecretTypeTool::MissingArgumentError)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `crystal spec spec/secret_type_tool_spec.cr` Expected: FAIL
(`key`/`field_name` undefined; old `reference` removed).

- [ ] **Step 3: Modify `src/playwright_secure_mcp/secret_type_tool.cr`**

Replace the `reference` method with `key`/`field_name`; keep `DEFINITION_JSON`,
`build_browser_type_arguments`, and the private helpers. Add
`require "./item"`.

```crystal
    def key(arguments : JSON::Any) : ItemKey
      ItemKey.new(vault_id: fetch_string(arguments, "vault"), item_id: fetch_string(arguments, "item"))
    end

    def field_name(arguments : JSON::Any) : String
      fetch_string(arguments, "field")
    end
```

(Delete `def reference`. `build_browser_type_arguments`, `required_string`,
`fetch_string`, `copy_optional` stay as-is.)

- [ ] **Step 4: Run test to verify it passes**

Run: `crystal spec spec/secret_type_tool_spec.cr` Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/playwright_secure_mcp/secret_type_tool.cr spec/secret_type_tool_spec.cr
git commit -m "SecretTypeTool yields ItemKey and field name from arguments"
```

---

### Task 9: Discovery tools + clear tool (`item_finders.cr`, `clear_items_tool.cr`)

**Files:**

- Create: `src/playwright_secure_mcp/item_finders.cr` (replaces
  `secret_finders.cr`)
- Create: `src/playwright_secure_mcp/clear_items_tool.cr`
- Delete: `src/playwright_secure_mcp/secret_finders.cr`,
  `spec/secret_finders_spec.cr`
- Test: `spec/item_finders_spec.cr` (create)

**Interfaces:**

- Consumes: `Item`, `ItemKey` (Task 1); `ItemCache` (Task 2); `ItemLocator`
  (Task 4); `WebsiteMatcher` (Task 3).
- Produces:
  - `abstract class ItemFinder` with `abstract def name`, `def definition`,
    `def find(page_url : String, arguments : JSON::Any) : Array(Item)`.
  - `ListItemsFinder` — `NAME = "browser_list_items"`; `find` lists logins,
    filters by `matches?`, reveals uncached survivors, caches, returns all
    surviving items (from cache).
  - `NameItemsFinder` — `NAME = "browser_find_items_by_name"`; requires `item`.
  - `TagItemsFinder` — `NAME = "browser_find_items_by_tag"`; requires `tag`.
  - `ClearItemsTool` — `NAME = "browser_clear_items"`; `#definition`,
    `#clear : String` (calls `ItemCache#clear`, returns a success message).
  - `class ItemFinder::MissingArgumentError < Exception`

Each finder: (1) list candidates (LOGIN summaries); (2) keep those where
`matcher.matches?(page_url, candidate)`; (3) `cache.has?` partition → `reveal`
the missing keys → `cache.store` each; (4) return the surviving keys resolved
from the cache (so cached + freshly revealed are uniform).

- [ ] **Step 1: Write the failing test**

Reuse `FAKE_OP_ITEMS` from Task 4 (login1 at `https://example.com/login`).

```crystal
# spec/item_finders_spec.cr
require "./spec_helper"

private FAKE_OP_ITEMS = File.expand_path("support/fake_op_items", __DIR__)

private def build
  cache = PlaywrightSecureMcp::ItemCache.new
  locator = PlaywrightSecureMcp::ItemLocator.new(op_command: FAKE_OP_ITEMS, account: nil, encryptor: cache)
  {cache, locator, PlaywrightSecureMcp::WebsiteMatcher.new}
end

Spectator.describe PlaywrightSecureMcp::ListItemsFinder do
  it "returns and caches login items valid for the current page" do
    cache, locator, matcher = build
    finder = PlaywrightSecureMcp::ListItemsFinder.new(cache: cache, item_locator: locator, website_matcher: matcher)
    items = finder.find("https://example.com/login", JSON.parse("{}"))
    expect(items.map(&.item_id)).to eq(["login1"])
    expect(cache.has?(PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1"))).to be_true
    # fields were revealed
    expect(items.first.fields.empty?).to be_false
  end

  it "drops items whose urls do not match the current page" do
    cache, locator, matcher = build
    finder = PlaywrightSecureMcp::ListItemsFinder.new(cache: cache, item_locator: locator, website_matcher: matcher)
    items = finder.find("https://other.com/", JSON.parse("{}"))
    expect(items.empty?).to be_true
  end
end

Spectator.describe PlaywrightSecureMcp::ClearItemsTool do
  it "clears the cache" do
    cache, _, _ = build
    cache.add_loose_secret("tok")
    tool = PlaywrightSecureMcp::ClearItemsTool.new(cache)
    message = tool.clear
    expect(message.downcase.includes?("clear")).to be_true
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `crystal spec spec/item_finders_spec.cr` Expected: FAIL (finders
undefined).

- [ ] **Step 3: Create `item_finders.cr` and `clear_items_tool.cr`; delete
      `secret_finders.cr`**

```crystal
# src/playwright_secure_mcp/item_finders.cr
require "json"
require "./item"
require "./item_cache"
require "./item_locator"
require "./website_matcher"

module PlaywrightSecureMcp
  abstract class ItemFinder
    class MissingArgumentError < Exception
    end

    abstract def name : String
    abstract def definition : JSON::Any
    # Returns the LOGIN items valid for `page_url` matching this tool's criteria,
    # revealing and caching any not already cached.
    abstract def find(page_url : String, arguments : JSON::Any) : Array(Item)

    def initialize(*, @cache : ItemCache, @item_locator : ItemLocator, @website_matcher : WebsiteMatcher)
    end

    # Shared pipeline: filter candidates to the page, reveal uncached, return
    # the surviving items from the cache.
    protected def resolve(page_url : String, candidates : Array(Item)) : Array(Item)
      matching = candidates.select { |candidate| @website_matcher.matches?(page_url, candidate) }
      missing = matching.map(&.key).reject { |key| @cache.has?(key) }
      @item_locator.reveal(missing).each { |item| @cache.store(item) }
      matching.compact_map { |candidate| @cache.fetch(candidate.key) }
    end

    protected def required_string(arguments : JSON::Any, key : String) : String
      value = arguments[key]?.try(&.as_s?)
      raise MissingArgumentError.new("#{key} is required") if value.nil? || value.empty?
      value
    end

    protected def optional_string(arguments : JSON::Any, key : String) : String?
      value = arguments[key]?.try(&.as_s?)
      value.nil? || value.empty? ? nil : value
    end
  end

  class ListItemsFinder < ItemFinder
    NAME = "browser_list_items"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_list_items",
        "description": "List the 1Password LOGIN items usable on the current browser page. Returns item identities and field metadata (no secret values) for use with browser_type_secret. Optionally scope to a vault.",
        "annotations": {"title": "List items for current page", "readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
        "inputSchema": {"type": "object", "properties": {"vault": {"type": "string", "description": "Vault ID or name to scope the search"}}}
      }
      JSON

    def name : String
      NAME
    end

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def find(page_url : String, arguments : JSON::Any) : Array(Item)
      resolve(page_url, @item_locator.list_logins(optional_string(arguments, "vault")))
    end
  end

  class NameItemsFinder < ItemFinder
    NAME = "browser_find_items_by_name"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_find_items_by_name",
        "description": "Find LOGIN items whose title matches, restricted to those usable on the current browser page. Returns item identities and field metadata (no secret values). Optionally scope to a vault.",
        "annotations": {"title": "Find items by name", "readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
        "inputSchema": {"type": "object", "properties": {"item": {"type": "string", "description": "Item title or ID to match"}, "vault": {"type": "string", "description": "Vault ID or name to scope the search"}}, "required": ["item"]}
      }
      JSON

    def name : String
      NAME
    end

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def find(page_url : String, arguments : JSON::Any) : Array(Item)
      needle = required_string(arguments, "item").downcase
      candidates = @item_locator.list_logins(optional_string(arguments, "vault"))
      named = candidates.select { |c| c.item_id == needle || c.title.downcase.includes?(needle) }
      resolve(page_url, named)
    end
  end

  class TagItemsFinder < ItemFinder
    NAME = "browser_find_items_by_tag"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_find_items_by_tag",
        "description": "Find LOGIN items carrying a tag, restricted to those usable on the current browser page. Returns item identities and field metadata (no secret values). Optionally scope to a vault.",
        "annotations": {"title": "Find items by tag", "readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
        "inputSchema": {"type": "object", "properties": {"tag": {"type": "string", "description": "1Password tag"}, "vault": {"type": "string", "description": "Vault ID or name to scope the search"}}, "required": ["tag"]}
      }
      JSON

    def name : String
      NAME
    end

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def find(page_url : String, arguments : JSON::Any) : Array(Item)
      tag = required_string(arguments, "tag")
      resolve(page_url, @item_locator.list_by_tag(tag, optional_string(arguments, "vault")))
    end
  end
end
```

```crystal
# src/playwright_secure_mcp/clear_items_tool.cr
require "json"
require "./item_cache"

module PlaywrightSecureMcp
  # `browser_clear_items`: drops all cached items (keeps the loose token).
  class ClearItemsTool
    NAME = "browser_clear_items"

    DEFINITION_JSON = <<-JSON
      {
        "name": "browser_clear_items",
        "description": "Clear the in-memory cache of revealed 1Password items. Takes no arguments.",
        "annotations": {"title": "Clear cached items", "readOnlyHint": false, "destructiveHint": false, "openWorldHint": false},
        "inputSchema": {"type": "object", "properties": {}}
      }
      JSON

    def initialize(@cache : ItemCache)
    end

    def name : String
      NAME
    end

    def definition : JSON::Any
      JSON.parse(DEFINITION_JSON)
    end

    def clear : String
      @cache.clear
      "Cleared the cached items."
    end
  end
end
```

Then
`git rm src/playwright_secure_mcp/secret_finders.cr spec/secret_finders_spec.cr`.

- [ ] **Step 4: Run test to verify it passes**

Run: `crystal spec spec/item_finders_spec.cr` Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add current-page-scoped item finders and browser_clear_items tool"
```

---

### Task 10: `Proxy` — dispatch, URL binding, on-demand fetch

**Files:**

- Modify: `src/playwright_secure_mcp/proxy.cr`
- Test: `spec/proxy_spec.cr` (rewrite for the new tools/flow)

**Interfaces:**

- Consumes: `ItemCache`, `ItemLocator`, `FieldSelector`, `PageUrl`,
  `ItemFinder` subclasses, `ClearItemsTool`, `SecretTypeTool`,
  `WebsiteMatcher`, `Redactor`, `SecretGuard`, `ItemResult`.
- Produces:
  `Proxy.new(*, client, upstream, item_cache : ItemCache,
  item_locator : ItemLocator, field_selector : FieldSelector, page_url : PageUrl,
  website_matcher : WebsiteMatcher, redactor, secret_guard, secret_type_tool,
  finders : Array(ItemFinder), clear_items_tool : ClearItemsTool,
  item_result : ItemResult, upstream_timeout = DEFAULT_UPSTREAM_TIMEOUT)`.

Behavioral changes vs today:

- `augment_tools_list` appends `secret_type_tool.definition`, each finder
  `definition`, and `clear_items_tool.definition`.
- Dispatch: `SecretTypeTool::NAME` → `handle_secret_call`;
  `ClearItemsTool::NAME` → clear; any finder name → `handle_find`; else
  `forward_tool_call` (guard unchanged).
- `handle_find`: read `page_url.current { ... }` (injected evaluate via
  `call_upstream`), call `finder.find(url, arguments)`, return
  `item_result.build`. On `PageUrl::UnavailableError` → error result.
- `handle_secret_call`: `key = secret_type_tool.key(args)`; item =
  `cache.fetch` or, on miss, `item_locator.reveal([key]).first?` → store or
  error; read `page_url.current`; `website_matcher.matches?(url, item)` else
  error; `field =
  field_selector.select(item, name)`; decrypt via
  `item_cache` cipher (add `ItemCache#decrypt(field.value)`); build args;
  inject `browser_type`; redact.
- `INSTRUCTIONS` string rewritten for the new tool names.

Add to `ItemCache` (Task 2 file) a decrypt helper used here:
`def decrypt(entry : EncryptedSecret) : String; String.new(@cipher.decrypt(entry)); end`
(Add this in Task 2's implementation and a one-line spec there; noted now for
the interface. If executing strictly in order, append it during Task 2.)

- [ ] **Step 1: Write the failing tests**

Rewrite `spec/proxy_spec.cr`. Extend `FakeUpstream` to answer
`browser_evaluate` with a configurable URL and to expose received type text.
Key cases (full harness mirrors the existing file's `wired`/`build_proxy`
structure — reuse it, swapping in the new constructor and a `FAKE_OP_ITEMS`
locator with a shared `ItemCache`):

```crystal
# In FakeUpstream#handle, add:
when "tools/call"
  arguments = request["params"]["arguments"]
  if request["params"]["name"].as_s == "browser_evaluate"
    reply(id, {"content" => JSON::Any.new([text_content(@page_url)]), "isError" => JSON::Any.new(false)})
    return
  end
  @received_browser_type_text = arguments["text"]?.try(&.as_s)
  reply(id, {"content" => JSON::Any.new([text_content("typed #{arguments["text"].as_s}")]), "isError" => JSON::Any.new(false)})
```

Tests:

1. `tools/list` includes `browser_list_items`, `browser_find_items_by_name`,
   `browser_find_items_by_tag`, `browser_clear_items`, `browser_type_secret`.
2. `browser_list_items` on page `https://example.com/login` returns `login1`.
3. `browser_type_secret` (vault `v1`, item `login1`, field `password`) on
   `https://example.com/login` types `pw` and the echoed reply is redacted to
   `typed «REDACTED»`.
4. `browser_type_secret` on `https://evil.com/` returns `isError: true` and the
   upstream never receives a `browser_type` (`received_browser_type_text` nil).
5. On-demand: with an empty cache, a `browser_type_secret` for `login1` on the
   matching page still succeeds (reveals then types).

(Write each as its own `it`, following the existing spec's request/response
pattern.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `crystal spec spec/proxy_spec.cr` Expected: FAIL (new constructor +
behavior not implemented).

- [ ] **Step 3: Implement the proxy changes**

Update the constructor and dispatch. Replace `dispatch_tool_call`,
`handle_find`, `handle_secret_call`, `augment_tools_list`, and `INSTRUCTIONS`:

```crystal
    private def dispatch_tool_call(message : JSON::Any) : Nil
      name = message.dig?("params", "name").try(&.as_s?)
      finder = name ? @finders.find { |candidate| candidate.name == name } : nil
      if name == SecretTypeTool::NAME
        track { handle_secret_call(message) }
      elsif name == ClearItemsTool::NAME
        track { handle_clear(message) }
      elsif finder
        track { handle_find(finder, message) }
      else
        forward_tool_call(message)
      end
    end

    private def handle_clear(message : JSON::Any) : Nil
      text = @clear_items_tool.clear
      send_to_client(text_result(message["id"], text))
    rescue error : Exception
      Log.error(exception: error) { "unexpected error clearing items" }
      send_to_client(error_result(message["id"], "clear failed: #{error.message}"))
    end

    private def handle_find(finder : ItemFinder, message : JSON::Any) : Nil
      original_id = message["id"]
      arguments = message.dig?("params", "arguments") || JSON::Any.new({} of String => JSON::Any)
      url = current_page_url
      items = finder.find(url, arguments)
      body = {"jsonrpc" => JSON::Any.new("2.0"), "id" => original_id, "result" => @item_result.build(items)}
      send_to_client(JSON::Any.new(body))
    rescue error : ItemLocator::Error | ItemFinder::MissingArgumentError | PageUrl::UnavailableError | UpstreamTimeoutError | KeyError | Channel::ClosedError
      send_to_client(error_result(message["id"], error.message || "item lookup failed"))
    rescue error : Exception
      Log.error(exception: error) { "unexpected error handling #{finder.name}" }
      send_to_client(error_result(message["id"], "item lookup failed: #{error.message}"))
    end

    private def handle_secret_call(message : JSON::Any) : Nil
      original_id = message["id"]
      arguments = message["params"]["arguments"]
      key = @secret_type_tool.key(arguments)
      item = fetch_or_reveal(key)
      raise SecretTypeTool::MissingArgumentError.new("no LOGIN item #{key.item_id}") if item.nil?

      url = current_page_url
      unless @website_matcher.matches?(url, item)
        send_to_client(error_result(original_id, "current page #{url} is not in this item's URL set"))
        return
      end

      field = @field_selector.select(item, @secret_type_tool.field_name(arguments))
      value = field.value
      raise FieldSelector::NotFoundError.new("field has no value") if value.nil?
      secret = @item_cache.decrypt(value)

      browser_arguments = @secret_type_tool.build_browser_type_arguments(arguments: arguments, secret: secret)
      params = JSON::Any.new({"name" => JSON::Any.new(SecretTypeTool::UPSTREAM_TOOL), "arguments" => browser_arguments})
      response = call_upstream("tools/call", params)
      log_upstream_failure(browser_arguments, response) if upstream_failed?(response)
      send_to_client(with_id(response, original_id))
    rescue error : ItemLocator::Error | FieldSelector::NotFoundError | SecretTypeTool::MissingArgumentError | PageUrl::UnavailableError | UpstreamTimeoutError | KeyError | Channel::ClosedError
      send_to_client(error_result(message["id"], error.message || "secret typing failed"))
    rescue error : Exception
      Log.error(exception: error) { "unexpected error handling secret call" }
      send_to_client(error_result(message["id"], "secret typing failed: #{error.message}"))
    end

    private def fetch_or_reveal(key : ItemKey) : Item?
      cached = @item_cache.fetch(key)
      return cached unless cached.nil?
      revealed = @item_locator.reveal([key]).first?
      @item_cache.store(revealed) unless revealed.nil?
      revealed
    end

    private def current_page_url : String
      @page_url.current { |params| call_upstream("tools/call", params) }
    end

    private def text_result(id : JSON::Any, text : String) : JSON::Any
      content = [JSON::Any.new({"type" => JSON::Any.new("text"), "text" => JSON::Any.new(text)})]
      result = {"content" => JSON::Any.new(content), "isError" => JSON::Any.new(false)}
      JSON::Any.new({"jsonrpc" => JSON::Any.new("2.0"), "id" => id, "result" => JSON::Any.new(result)})
    end
```

In `augment_tools_list`, after appending finder definitions, add:
`tools << @clear_items_tool.definition`.

Rewrite `INSTRUCTIONS` to describe `browser_list_items` /
`browser_find_items_by_name` / `browser_find_items_by_tag` (return items usable
on the current page, no values), `browser_type_secret` (types a field of a
chosen item; only allowed on a page in the item's URL set), and
`browser_clear_items`.

Update the constructor signature and instance vars accordingly (`@item_cache`,
`@item_locator`, `@field_selector`, `@page_url`, `@website_matcher`,
`@finders :
Array(ItemFinder)`, `@clear_items_tool`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `crystal spec spec/proxy_spec.cr` Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/playwright_secure_mcp/proxy.cr spec/proxy_spec.cr
git commit -m "Proxy: current-page-scoped discovery, URL-bound typing, clear tool"
```

---

### Task 11: `Redactor` + `SecretGuard` on `ItemCache`

**Files:**

- Modify: `src/playwright_secure_mcp/redactor.cr`,
  `src/playwright_secure_mcp/secret_guard.cr`
- Test: `spec/redactor_spec.cr`, `spec/secret_guard_spec.cr` (update
  constructors)

**Interfaces:**

- Consumes: `ItemCache#each_plaintext` (Task 2).
- Produces: `Redactor.new(cache : ItemCache)`,
  `SecretGuard.new(cache : ItemCache)` — same public methods (`redact`,
  `check`), now iterating the item cache.

Only the constructor parameter type changes (`SecretVault` → `ItemCache`); both
already depend solely on `each_plaintext`. `SecretGuard#check_references` still
rejects the `op://` prefix (define `SecretGuard::REFERENCE_PREFIX = "op://"`
locally since `SecretResolver` is being deleted).

- [ ] **Step 1: Update the specs to build an `ItemCache` with a stored item**

In `spec/redactor_spec.cr` and `spec/secret_guard_spec.cr`, replace
`SecretVault.new` + `store(ref, secret)` with an `ItemCache` holding an item
whose field value is the secret (use the `field`/`item` helpers from Task 2's
spec, or `add_loose_secret(secret)` for brevity). Example:

```crystal
let(cache) do
  c = PlaywrightSecureMcp::ItemCache.new
  c.add_loose_secret("super-secret-value")
  c
end
let(redactor) { PlaywrightSecureMcp::Redactor.new(cache) }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `crystal spec spec/redactor_spec.cr spec/secret_guard_spec.cr` Expected:
FAIL (constructors expect `SecretVault`).

- [ ] **Step 3: Change the constructor parameter types**

In `redactor.cr`: `def initialize(@cache : ItemCache)` and change `@vault` →
`@cache`; `require "./item_cache"`. In `secret_guard.cr`: same, plus define
`REFERENCE_PREFIX = "op://"` and drop `require "./secret_resolver"` /
`require "./secret_type_tool"` if only used for the prefix; keep
`SecretTypeTool::NAME` reference (require `./secret_type_tool`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `crystal spec spec/redactor_spec.cr spec/secret_guard_spec.cr` Expected:
PASS.

- [ ] **Step 5: Commit**

```bash
git add src/playwright_secure_mcp/redactor.cr src/playwright_secure_mcp/secret_guard.cr spec/redactor_spec.cr spec/secret_guard_spec.cr
git commit -m "Point Redactor and SecretGuard at the item cache"
```

---

### Task 12: Wiring — `application.cr`, requires, delete `SecretResolver`

**Files:**

- Modify: `src/playwright_secure_mcp/application.cr`,
  `src/playwright_secure_mcp.cr`
- Delete: `src/playwright_secure_mcp/secret_resolver.cr`,
  `spec/secret_resolver_spec.cr`
- Test: full `rake spec` + `rake lint` + a manual smoke check

**Interfaces:**

- Consumes: everything above.
- Produces: a running proxy wired with `ItemCache`, `ItemLocator` (with the
  cache as encryptor), the three finders, `ClearItemsTool`, `FieldSelector`,
  `PageUrl`.

- [ ] **Step 1: Update `application.cr`**

Build the cache first, pass it as `ItemLocator`'s encryptor, store the token as
a loose secret, and construct the new proxy:

```crystal
      cipher = CipherSelector.for_host.select(require_hardware: configuration.require_hardware_key)
      Log.info { "cache key protection: #{cipher.description}" }
      cache = ItemCache.new(cipher)
      item_locator = ItemLocator.new(
        op_command: configuration.op_command,
        account: token ? nil : account,
        service_account_token: token,
        encryptor: cache)
      # token fetched before this point; store it for redaction/guard coverage
      cache.add_loose_secret(token) if token && !token.empty?

      finders = [
        ListItemsFinder.new(cache: cache, item_locator: item_locator, website_matcher: WebsiteMatcher.new),
        NameItemsFinder.new(cache: cache, item_locator: item_locator, website_matcher: WebsiteMatcher.new),
        TagItemsFinder.new(cache: cache, item_locator: item_locator, website_matcher: WebsiteMatcher.new),
      ] of ItemFinder

      proxy = Proxy.new(
        client: StdioTransport.new(input: STDIN, output: STDOUT),
        upstream: upstream_transport,
        item_cache: cache,
        item_locator: item_locator,
        field_selector: FieldSelector.new,
        page_url: PageUrl.new,
        website_matcher: WebsiteMatcher.new,
        redactor: Redactor.new(cache),
        secret_guard: SecretGuard.new(cache),
        secret_type_tool: SecretTypeTool.new,
        finders: finders,
        clear_items_tool: ClearItemsTool.new(cache),
        item_result: ItemResult.new)
      proxy.run
```

Remove the `fetch_token` `vault.store(...)` call's old vault usage — keep token
fetching (`TokenFetcher`) but return the token so `add_loose_secret` handles
it. Drop the `SecretResolver` construction. Update `require`s at the top:
remove `./secret_resolver` and `./secret_vault`; add `./item_cache`,
`./field_selector`, `./page_url`, `./item_finders`, `./clear_items_tool`.

- [ ] **Step 2: Update `src/playwright_secure_mcp.cr` requires**

Remove `require "./playwright_secure_mcp/secret_resolver"`,
`require "./playwright_secure_mcp/secret_vault"`,
`require "./playwright_secure_mcp/secret_finders"`. Add
`require "./playwright_secure_mcp/item_cache"`,
`require "./playwright_secure_mcp/field_selector"`,
`require "./playwright_secure_mcp/page_url"`,
`require "./playwright_secure_mcp/item_finders"`,
`require "./playwright_secure_mcp/clear_items_tool"`. Then
`git rm src/playwright_secure_mcp/secret_resolver.cr spec/secret_resolver_spec.cr`.

- [ ] **Step 3: Build + full test + lint**

Run:

```bash
rake build && rake spec && rake lint
```

Expected: compiles; all specs PASS; ameba clean. Fix any compile errors from
lingering `SecretVault`/`SecretResolver`/`Item` references surfaced here.

- [ ] **Step 4: Manual smoke check (verify skill)**

Run the built binary against a real page and 1Password to confirm the
end-to-end flow. Follow the `verify` skill. Minimum:

- `browser_navigate` to a login page in the item's URL set;
- `browser_list_items` returns the item (no values);
- `browser_type_secret` types the password (page shows it filled);
- navigate off-domain, `browser_type_secret` refuses;
- `browser_clear_items` succeeds; a subsequent `browser_type_secret`
  re-reveals.

Because a rebuilt binary needs a full MCP process respawn (not
`/mcp reconnect`), restart the MCP server before testing.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Wire item cache, finders, and URL-bound typing; remove SecretResolver"
```

---

## Self-review notes

- **Spec coverage:** eager reveal (Task 4/9), on-demand fetch (Task 10
  `fetch_or_reveal`), LOGIN-only (Task 4 `reveal`/`list_logins`), URL binding
  (Task 3 + Task 10), match rule host+path (Task 3 `path_matches?`), tool
  rename + `browser_list_items` (Task 9), field metadata output (Task 7),
  write-once + `browser_clear_items` (Task 2 + Task 9), batched reveal (Task
  4), token as loose secret (Task 2 + Task 12), redactor/guard coverage (Task
  11), retire SecretResolver (Task 12). All covered.
- **Type consistency:** `ItemCache` exposes
  `encrypt`/`decrypt`/`store`/`fetch`/
  `has?`/`clear`/`add_loose_secret`/`each_plaintext`;
  `ItemLocator.new(...,
  encryptor: cache)`; finders take
  `cache:`/`item_locator:`/`website_matcher:`; `Proxy.new` names match Task 10
  and Task 12. `ItemCache#decrypt` is required by Task 10 — ensure it is added
  in Task 2 (append the method + a round-trip spec line there).
- **Fixtures:** `fake_op_items` bash fixture runs on the dev/macOS host as the
  other fixtures do; CI Alpine jobs run unit specs on the host toolchain, but
  if a musl container path is exercised, remember `apk add bash` (existing CI
  note).
