# Live TOTP fetch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make 1Password TOTP fields typable via `browser_type_secret` by
fetching the current code live from `op` on every request, never caching it for
reuse, while registering it with the redactor/guard under a 60 s expiry.

**Architecture:** `ItemCache` gains an injectable clock and an expiring-secret
list (redaction-only, purged lazily). `ItemLocator` gains a live `--otp` fetch
and an explicit OTP cache-exclusion. `Proxy#handle_secret_call` branches on the
OTP field type, fetches live, registers the code, and purges expired entries at
its cache touchpoints.

**Tech Stack:** Crystal ≥ 1.20 (`Time`, procs, `Process`), Spectator specs.

## Global Constraints

- Crystal `>= 1.20`; edit Crystal with Edit/Write only (never a Serena
  symbol-editing tool — it corrupts Crystal files).
- Secrets: the live OTP code and the `otpauth://` seed must never be written to
  a durable field value, never on a command line, never logged/echoed
  unredacted. Only the `--otp` code is used; the seed is never cached.
- `OTP_TYPE = "OTP"` is defined once on `ItemLocator` (beside `CONCEALED_TYPE`)
  and referenced by `Proxy` as `ItemLocator::OTP_TYPE` (Proxy already requires
  `./item_locator`; no new dependency).
- `OTP_TTL = 60.seconds` and the expiring-secret machinery live on `ItemCache`.
- `rake spec` / `rake lint` / `rake build` all green.
- The project uses cspell (`cspell.dict`, one lowercase word per line, sorted).
  Before committing, run cspell on every changed file and add legitimate
  flagged words to `cspell.dict` in sorted position.
- ONE `feat:` commit at the end (Task 4), body an unordered bullet list ≤72
  cols, no AI/Claude/Copilot references. Do not commit until Task 4.
- Ad-hoc `crystal spec` needs `--link-flags=-fuse-ld=/usr/bin/ld`; rake handles
  it.

All tasks land together in the single Task 4 commit; Tasks 1–3 build up and are
each independently testable.

---

### Task 1: `ItemCache` — injectable clock + expiring secrets

**Files:**

- Modify: `src/playwright_secure_mcp/item_cache.cr`
- Test: `spec/item_cache_spec.cr`

**Interfaces produced:** `ItemCache.new(cipher?, *, clock : -> Time)`,
`#add_expiring_secret(secret : String) : Nil`, `#purge_expired : Nil`,
`ItemCache::OTP_TTL`.

- [ ] **Step 1: Failing test** — append inside the describe block in
      `spec/item_cache_spec.cr`:

```crystal
  it "redacts an expiring secret until it is purged past its ttl" do
    now = Time.utc(2026, 1, 1, 0, 0, 0)
    clock_cache = PlaywrightSecureMcp::ItemCache.new(clock: -> { now })
    clock_cache.add_expiring_secret("otp-code")

    present = [] of String
    clock_cache.each_plaintext { |secret| present << secret }
    expect(present).to eq(["otp-code"])

    now = now + PlaywrightSecureMcp::ItemCache::OTP_TTL - 1.second
    clock_cache.purge_expired
    still = [] of String
    clock_cache.each_plaintext { |secret| still << secret }
    expect(still).to eq(["otp-code"])

    now = now + 2.seconds # now past ttl
    clock_cache.purge_expired
    gone = [] of String
    clock_cache.each_plaintext { |secret| gone << secret }
    expect(gone).to be_empty
  end

  it "clear drops expiring secrets" do
    dropped = PlaywrightSecureMcp::ItemCache.new
    dropped.add_expiring_secret("otp-code")
    dropped.clear
    got = [] of String
    dropped.each_plaintext { |secret| got << secret }
    expect(got).to be_empty
  end
```

- [ ] **Step 2: Run — FAIL**

Run: `crystal spec spec/item_cache_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: FAIL (`add_expiring_secret`/`purge_expired`/`OTP_TTL`/`clock`
undefined).

- [ ] **Step 3: Implement** in `src/playwright_secure_mcp/item_cache.cr`:

Add the TTL constant and record near the top of the class:

```crystal
    OTP_TTL = 60.seconds

    private record ExpiringSecret, entry : EncryptedSecret, purge_at : Time
```

Change the constructor to accept an injectable clock and init the list:

```crystal
def initialize(@cipher : SecretCipher = InMemoryCipher.new, *, @clock : Proc(Time) = ->{ Time.utc })
  @items = {} of ItemKey => Item
  @loose = [] of EncryptedSecret
  @expiring = [] of ExpiringSecret
  @service_token = nil.as(EncryptedSecret?)
end
```

Add the two methods (e.g. after `add_loose_secret`):

```crystal
    # Stores a secret that is redacted/guarded until purge_expired drops it past
    # OTP_TTL. Used for live one-time-password codes, which are never cached for
    # reuse but must not leak into logs while being typed.
    def add_expiring_secret(secret : String) : Nil
      @expiring << ExpiringSecret.new(@cipher.encrypt(secret.to_slice), @clock.call + OTP_TTL)
    end

    # Drops every expiring secret whose window has closed.
    def purge_expired : Nil
      now = @clock.call
      @expiring.reject! { |entry| now >= entry.purge_at }
    end
```

Include them in redaction/guard and clear:

```crystal
def clear : Nil
  @items.clear
  @expiring.clear
end
```

In `collect_entries`, after `entries.concat(@loose)`:

```crystal
@expiring.each { |expiring| entries << expiring.entry }
```

- [ ] **Step 4: Run — PASS**

Run: `crystal spec spec/item_cache_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS (existing cache specs still green — `clear` still drops items
and keeps loose secrets; the new specs pass).

### Task 2: `ItemLocator` — OTP exclusion + live `--otp` fetch

**Files:**

- Modify: `src/playwright_secure_mcp/item_locator.cr`
- Modify: `spec/support/fake_op_items`
- Test: `spec/item_locator_spec.cr`

**Interfaces produced:** `ItemLocator::OTP_TYPE`,
`ItemLocator#one_time_password(key : ItemKey) : String`; `cache_value` returns
nil for OTP fields.

- [ ] **Step 1: Extend the fake op** — in `spec/support/fake_op_items`:

(a) Add an OTP field to the `*login1*` reveal object so the exclusion is
exercised. In the `*login1*` branch, inside that item's `"fields":[ ... ]`
array, add one more field object (keep the existing three):

```
,{"id":"otp","type":"OTP","label":"one-time password","value":"otpauth://totp/Example?secret=SEED","totp":"123456"}
```

(b) Add an `--otp` handler. Near the other `item get` branches, before the
final `exit 1`, add:

```bash
if [ "$1" = "item" ] && [ "$2" = "get" ]; then
  for a in "$@"; do [ "$a" = "--otp" ] && { [ "$3" = "login1" ] && { printf '135790\n'; exit 0; } || exit 1; }; done
fi
```

- [ ] **Step 2: Failing tests** — in `spec/item_locator_spec.cr`:

Update the existing reveal size assertion (login1 now has 4 fields): change
`expect(fields.size).to eq(3)` to `expect(fields.size).to eq(4)` in the
"reveals items in one batched call" test.

Append new tests inside the describe block:

```crystal
  it "does not cache the value of an OTP field" do
    items = locator.reveal([PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1")])
    expect(items.first.fields["otp"].type).to eq(PlaywrightSecureMcp::ItemLocator::OTP_TYPE)
    expect(items.first.fields["otp"].value).to be_nil
  end

  it "fetches the current one-time password live" do
    code = locator.one_time_password(PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "login1"))
    expect(code).to eq("135790")
  end

  it "raises when op has no one-time password for the item" do
    expect { locator.one_time_password(PlaywrightSecureMcp::ItemKey.new(vault_id: "v1", item_id: "missing")) }
      .to raise_error(PlaywrightSecureMcp::ItemLocator::Error)
  end
```

- [ ] **Step 3: Run — FAIL**

Run: `crystal spec spec/item_locator_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: FAIL (`OTP_TYPE`/`one_time_password` undefined; OTP field currently
has no exclusion path yet — the size/exclusion assertions drive it).

- [ ] **Step 4: Implement** in `src/playwright_secure_mcp/item_locator.cr`:

Add the constant beside `CONCEALED_TYPE`:

```crystal
OTP_TYPE = "OTP"
```

In `cache_value`, add the explicit exclusion as the first guard after the
empty-check:

```crystal
private def cache_value(*, type : String, purpose : String?, value : String?) : EncryptedSecret?
  return nil if value.nil? || value.empty?
  return nil if type == OTP_TYPE
  return nil unless type == CONCEALED_TYPE || (purpose && CREDENTIAL_PURPOSES.includes?(purpose))
  @encryptor.encrypt(value)
end
```

Add the live fetch (e.g. after `reveal`):

```crystal
# Fetches the item's current one-time password live. The code is a
# short-lived secret: it is never cached for reuse and never placed on a
# command line (op prints it to stdout).
def one_time_password(key : ItemKey) : String
  code = run(["item", "get", key.item_id, "--otp"], vault: key.vault_id).strip
  raise Error.new("op returned no one-time password for #{key.item_id}") if code.empty?
  code
end
```

- [ ] **Step 5: Run — PASS**

Run: `crystal spec spec/item_locator_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS.

### Task 3: `Proxy` typing branch + purge + docs

**Files:**

- Modify: `src/playwright_secure_mcp/proxy.cr`
- Modify: `src/playwright_secure_mcp/secret_type_tool.cr`
- Test: `spec/proxy_spec.cr` (follow the existing secret-typing harness)

**Interfaces consumed:** `ItemCache#add_expiring_secret`, `#purge_expired`,
`ItemLocator#one_time_password`, `ItemLocator::OTP_TYPE`.

- [ ] **Step 1: Failing test** — in `spec/proxy_spec.cr`, mirror the existing
      successful `browser_type_secret` test but target an OTP field. Use the
      same fake upstream/op harness already used there; the item must expose an
      OTP field (the fake op reveal for that item includes
      `{"type":"OTP",...}`), and the page URL must match the item. Assert:
  - the upstream `browser_type` call receives the live code (the fake `--otp`
    value), and
  - the client reply is the upstream success (not an error).

  If proxy_spec has no OTP fixture item yet, add one to its fake op (an item
  with an OTP field + a matching url), following the file's existing fixture
  style. Name the test e.g.
  `"types a one-time password fetched live for an OTP field"`.

- [ ] **Step 2: Run — FAIL**

Run: `crystal spec spec/proxy_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: FAIL (OTP field → old code path raises "field has no value").

- [ ] **Step 3: Implement** in `src/playwright_secure_mcp/proxy.cr`:

In `handle_secret_call`, replace the value-resolution lines

```crystal
field = @field_selector.select(item, @secret_type_tool.field_name(arguments))
value = field.value
raise FieldSelector::NotFoundError.new("field has no value") if value.nil?
secret = @item_cache.decrypt(value)
```

with the OTP branch:

```crystal
field = @field_selector.select(item, @secret_type_tool.field_name(arguments))
secret =
  if field.type == ItemLocator::OTP_TYPE
    code = @item_locator.one_time_password(item.key)
    @item_cache.add_expiring_secret(code)
    code
  else
    value = field.value
    raise FieldSelector::NotFoundError.new("field has no value") if value.nil?
    @item_cache.decrypt(value)
  end
```

(The `ItemLocator::Error` from `one_time_password` is already in the rescue
list of `handle_secret_call`.)

Add `@item_cache.purge_expired` at the two touchpoints:

In `fetch_or_reveal`, as the first line:

```crystal
private def fetch_or_reveal(key : ItemKey) : Item?
  @item_cache.purge_expired
  cached = @item_cache.fetch(key)
  # ... unchanged ...
```

In `handle_find`, right after reading `original_id`:

```crystal
private def handle_find(finder : ItemFinder, message : JSON::Any) : Nil
  original_id = message["id"]
  @item_cache.purge_expired
  # ... unchanged ...
```

Update `INSTRUCTIONS` — append one sentence before the closing text (keep it
one string literal), e.g. after the "username or password" sentence:

```
"A one-time-password (TOTP) field is typed the same way; its code is fetched " \
"live from 1Password and never cached. "
```

- [ ] **Step 4:** In `src/playwright_secure_mcp/secret_type_tool.cr`, extend
      the `browser_type_secret` `description` in `DEFINITION_JSON` to mention
      TOTP, e.g. append to the description string:
      `One-time-password (TOTP) fields are
  supported and fetched live.` (Keep
      it valid JSON — it is inside the here-doc string; escape quotes as the
      existing text does.)

- [ ] **Step 5: Run — PASS**

Run: `crystal spec spec/proxy_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS (existing secret-typing and instruction/definition tests still
green; update any instruction/description assertion that pins the exact text).

### Task 4: cspell, full gate, commit

- [ ] **Step 1: cspell** — run on every changed file plus the design/plan docs:

```
cspell --no-progress --no-summary \
  src/playwright_secure_mcp/item_cache.cr src/playwright_secure_mcp/item_locator.cr \
  src/playwright_secure_mcp/proxy.cr src/playwright_secure_mcp/secret_type_tool.cr \
  spec/item_cache_spec.cr spec/item_locator_spec.cr spec/proxy_spec.cr \
  spec/support/fake_op_items \
  docs/superpowers/specs/2026-07-20-totp-live-fetch-design.md \
  docs/superpowers/plans/2026-07-20-totp-live-fetch.md
```

Add every legitimate flagged word to `cspell.dict` in sorted position (expected
at least: `otp`, `totp`, `otpauth`, `hotp`, `touchpoints`; plus any others).
Re-run until exit 0.

- [ ] **Step 2: Full gate**

Run: `rake spec && rake lint && rake build` Expected: all green.

- [ ] **Step 3: Commit** (single `feat:` commit)

```bash
git add src/playwright_secure_mcp/item_cache.cr src/playwright_secure_mcp/item_locator.cr \
        src/playwright_secure_mcp/proxy.cr src/playwright_secure_mcp/secret_type_tool.cr \
        spec/item_cache_spec.cr spec/item_locator_spec.cr spec/proxy_spec.cr \
        spec/support/fake_op_items cspell.dict \
        docs/superpowers/specs/2026-07-20-totp-live-fetch-design.md \
        docs/superpowers/plans/2026-07-20-totp-live-fetch.md
git commit   # feat: type one-time passwords fetched live from 1Password
```

Body bullets (do not mention the cspell.dict tag-along):

- type OTP fields via browser_type_secret by fetching the code live with op
  item get --otp on every request
- never cache the code for reuse; register it as an expiring secret so the
  redactor and guard mask it, purged after 60s and on browser_close
- exclude OTP fields from durable field-value caching
- purge expired codes when accessing an item or listing items

---

## Self-review notes

- **Spec coverage:** expiring cache + clock + purge + clear (Task 1); OTP
  cache-exclusion + live fetch (Task 2); typing branch + purge touchpoints +
  discoverability docs (Task 3); never-cache-seed enforced by the OTP exclusion
  (only `totp`/`--otp` used, `value` never cached). All covered.
- **Type consistency:** `add_expiring_secret(String) : Nil`,
  `purge_expired :
  Nil`, `ItemCache.new(cipher?, *, clock : Proc(Time))`,
  `one_time_password(ItemKey) : String`, `ItemLocator::OTP_TYPE`. Proxy
  references `ItemLocator::OTP_TYPE` (already requires item_locator).
- **No placeholders:** unit code is complete; the Proxy integration test is
  described against the established proxy_spec harness (its exact fixtures live
  in that file), with concrete assertions.
