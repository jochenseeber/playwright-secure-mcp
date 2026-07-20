# Live TOTP fetch (never cache the code for reuse) — design

Date: 2026-07-20

## Goal

Let the LLM type a 1Password TOTP into a page. A time-based one-time password
changes every period, and `op` supplies no validity/expiry information, so the
code is **fetched live on every request** and never reused from a cache. The
fetched code is still a secret, so it is registered with the redaction/guard
gate with a short expiry (60 s) purely so it cannot leak into logs/responses
while it is being typed, then purged.

Today a TOTP field (op field `type: "OTP"`) is surfaced in discovery as
metadata but has no cached value (`ItemLocator#cache_value` excludes it), so
`browser_type_secret` on it fails at `value = field.value` (nil → "field has no
value"). This feature makes that path work.

## Decisions (settled during brainstorming)

- **Interface:** reuse `browser_type_secret`. When the selected field is an
  OTP-type field, fetch the current code live instead of decrypting a cached
  value. No new tool.
- **Never cached for reuse:** every OTP type request fetches fresh via
  `op item get <id> --otp`. No reuse window, no capture-on-reveal. (op returns
  no expiry, so a reused code could already have rolled over; always fetching
  fresh avoids that.)
- **Redaction only, expiring:** the fetched code is added to the cache with a
  `OTP_TTL = 60.seconds` expiry so the redactor and guard mask it while it is
  in flight; it is never stored as a durable `Field#value` and is dropped on
  `browser_close`.
- **Cleanup:** lazy global `purge_expired` at two touchpoints — accessing an
  item directly, and fetching all items (discovery). No background timer.

## Design

### 1. Expiring secrets (`ItemCache`)

A list of time-bounded secrets, separate from `@loose`. `ItemCache` owns an
injectable clock so purge timing is centralized and specs are deterministic.

```
OTP_TTL = 60.seconds

record ExpiringSecret, entry : EncryptedSecret, purge_at : Time

def initialize(@cipher : SecretCipher = InMemoryCipher.new, *, @clock : -> Time = ->{ Time.utc })
  # ... existing ...
  @expiring = [] of ExpiringSecret
end

# Encrypts and stores a secret that is redacted/guarded until it is purged.
def add_expiring_secret(secret : String) : Nil
  @expiring << ExpiringSecret.new(@cipher.encrypt(secret.to_slice), @clock.call + OTP_TTL)
end

# Drops every expiring secret past its deadline.
def purge_expired : Nil
  now = @clock.call
  @expiring.reject! { |e| now >= e.purge_at }
end
```

- `collect_entries` (feeds both `each_plaintext` → redactor **and**
  `SecretGuard`) appends `@expiring.map(&.entry)`, so a live code is masked in
  logs/responses and blocked from other upstream tools until purged.
- `clear` (on `browser_close`) also empties `@expiring`.
- The default clock is `->{ Time.utc }`; `Application` is unchanged. Specs
  inject a controllable clock to advance past the 60 s deadline.

### 2. Live fetch (`ItemLocator#one_time_password(key : ItemKey) : String`)

Reuses the existing `run`/auth/timeout/error infrastructure:

```
def one_time_password(key : ItemKey) : String
  code = run(["item", "get", key.item_id, "--otp"], vault: key.vault_id).strip
  raise Error.new("op returned no one-time password for #{key.item_id}") if code.empty?
  code
end
```

`op item get <id> --vault <v> --otp` prints the current code on stdout in both
auth modes (verified against a real item); failure raises `ItemLocator::Error`,
already handled by `handle_secret_call`'s rescue.

### 3. Typing flow (`Proxy#handle_secret_call`)

Unchanged through item fetch, URL authorization, and field selection. Then:

```
field = @field_selector.select(item, field_name)
secret =
  if field.type == ItemLocator::OTP_TYPE                   # "OTP"
    code = @item_locator.one_time_password(item.key)
    @item_cache.add_expiring_secret(code)
    code
  else
    value = field.value
    raise FieldSelector::NotFoundError.new("field has no value") if value.nil?
    @item_cache.decrypt(value)
  end
# build browser_type arguments with `secret`, call upstream, reply (unchanged)
```

- Reached only after `@website_matcher.matches?` passes, so `op` is never
  invoked for an unauthorized page.
- The code is added to the cache **before** the upstream `browser_type` call,
  so `log_upstream_failure` and `send_to_client` redaction already mask it.
- No reuse: a second type request fetches a fresh code.

`OTP_TTL` lives on `ItemCache`.

### 4. Cleanup triggers (`Proxy`)

Lazy global `purge_expired`, no timer:

- `fetch_or_reveal(key)` — accessing an item directly (the secret-type path).
- `handle_find(finder, message)` — discovery / fetching all items.

### 5. Never durable (`ItemLocator#cache_value`)

Make non-caching of the durable field value explicit and robust:

```
OTP_TYPE = "OTP"
# ...
return nil if type == OTP_TYPE
```

Already effectively true (OTP is neither `CONCEALED` nor a username/password
purpose); this states the intent and holds even if op ever tags an OTP field as
concealed. `op`'s revealed OTP value is the `otpauth://` **seed** (a long-term
secret), so it must never be cached — only the live `totp` code is used, via
`--otp`. The `OTP_TYPE` constant is defined on `ItemLocator` (the
cache-exclusion site) and referenced by the typing branch in `Proxy` as
`ItemLocator::OTP_TYPE`.

### 6. Discoverability

OTP fields already appear in discovery with `type: "OTP"`. Update:

- `SecretTypeTool` definition `description`: note one-time-password / TOTP
  fields are supported and fetched live.
- `Proxy::INSTRUCTIONS`: one sentence that a TOTP field is typed the same way
  and is fetched live (never cached).

## Security invariants (unchanged or strengthened)

- A live code is redacted and guarded from fetch until purge (≤ 60 s) and on
  `browser_close`.
- The code is never written to a durable field value, the `otpauth` seed is
  never cached, nothing is on a command line (op prints to stdout), and the
  code is only fetched after the URL-authorization gate.
- No client-facing behavior change other than TOTP fields becoming typable.

## Testing

- `ItemCache` (injected clock): `add_expiring_secret` → present in
  `each_plaintext`; after advancing the clock past `OTP_TTL`, `purge_expired`
  removes it (before, it keeps it); `clear` drops it.
- `ItemLocator#one_time_password`: fake op `item get <id> --vault <v> --otp`
  returns a code → stripped and returned; empty/failed op →
  `ItemLocator::Error`.
- `ItemLocator#cache_value`: an `OTP` field reveals with a `nil` field value
  (metadata only, not cached).
- `Proxy` secret call on an OTP field: live fetch path → the code is added to
  the cache and the upstream `browser_type` receives it; URL gate still
  enforced (unauthorized page → refusal, no op call); a previously-added code
  is purged on the next item access / discovery; failed-upstream log is
  redacted.

## Out of scope

- HOTP / counter-based or multiple-OTP-per-item handling (`--otp` uses the
  item's primary OTP).
- Reusing a code across calls / caching for reuse (op supplies no expiry, so
  every request fetches fresh).
- Configurable TTL or caching policy.
