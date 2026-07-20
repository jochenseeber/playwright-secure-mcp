# Live TOTP fetch (never cache one-time passwords) — design

Date: 2026-07-20

## Goal

Let the LLM type a 1Password TOTP into a page. A time-based one-time password
is worthless once cached (it changes every period), so it must be fetched
**live** from `op` at type-time and never stored as a durable field value. The
live code is still a secret, so it must be covered by the redaction/guard gate
for as long as it is valid.

Today a TOTP field (op field `type: "OTP"`) is surfaced in discovery as
metadata but has no cached value (`ItemLocator#cache_value` excludes it), so
`browser_type_secret` on it fails at `value = field.value` (nil → "field has no
value"). This feature makes that path work by fetching the current code live.

## Decisions (settled during brainstorming)

- **Interface:** reuse `browser_type_secret`. When the selected field is an
  OTP-type field, fetch the current code live instead of decrypting a cached
  value. No new tool.
- **Protection:** add the fetched code to the cache with an **expiration**, so
  the redactor and guard cover it while it is valid; purge lazily.
- **TTL:** `OTP_TTL = 60.seconds` (one standard TOTP period plus clock-skew
  headroom).
- **Cleanup:** global `purge_expired` at two natural touchpoints — accessing an
  item directly, and fetching all items (discovery). No background timer.

## Design

### 1. Flow (`Proxy#handle_secret_call`)

Unchanged through item fetch, URL authorization, and field selection. Then
branch on the selected field's op type:

```
field = @field_selector.select(item, field_name)
secret =
  if field.type == FieldSelector::OTP_TYPE          # "OTP"
    code = @item_locator.one_time_password(item.key)
    @item_cache.add_expiring_secret(code, Time.utc + OTP_TTL)
    code
  else
    value = field.value
    raise FieldSelector::NotFoundError.new("field has no value") if value.nil?
    @item_cache.decrypt(value)
  end
# build browser_type arguments with `secret`, call upstream, reply (unchanged)
```

- The OTP branch is reached only after `@website_matcher.matches?` passes, so
  `op` is never invoked for an unauthorized page.
- The code is added to the cache **before** the upstream `browser_type` call,
  so `log_upstream_failure` (which redacts via `@redactor` → `each_plaintext`)
  already masks it, and `send_to_client` redaction covers any echo.
- No ensure-removal: the entry lives until it expires and is purged (below).

`OTP_TYPE` lives on `FieldSelector` (it already owns field-type knowledge);
`OTP_TTL` is a `Proxy` constant.

### 2. Live fetch (`ItemLocator#one_time_password(key : ItemKey) : String`)

Reuses the existing `run`/auth/`invoke` infrastructure (service-token env or
`--account`, timeout, error wrapping):

```
def one_time_password(key : ItemKey) : String
  output = run(["item", "get", key.item_id, "--otp"], vault: key.vault_id)
  code = output.strip
  raise Error.new("op returned no one-time password for #{key.item_id}") if code.empty?
  code
end
```

- `op item get <id> --vault <v> --otp` prints the current code on stdout; works
  in both auth modes. A failure (no OTP field, op error) raises
  `ItemLocator::Error`, already handled by `handle_secret_call`'s rescue.
- `--otp` returns the item's primary one-time password; multiple OTP fields per
  item is out of scope.

### 3. Expiring secrets (`ItemCache`)

New list parallel to `@loose`, holding time-bounded secrets:

```
record ExpiringSecret, entry : EncryptedSecret, expires_at : Time

@expiring = [] of ExpiringSecret

# Encrypts and stores a secret that stops being redacted after expires_at.
def add_expiring_secret(secret : String, expires_at : Time) : Nil
  @expiring << ExpiringSecret.new(@cipher.encrypt(secret.to_slice), expires_at)
end

# Drops every expiring secret whose window has closed.
def purge_expired(now : Time) : Nil
  @expiring.reject! { |e| e.expires_at <= now }
end
```

- `collect_entries` (feeds both `each_plaintext` → redactor **and**
  `SecretGuard`) appends `@expiring.map(&.entry)`. So while a code is valid it
  is masked in logs/responses and blocked from being sent to other upstream
  tools.
- `clear` (invoked on `browser_close`) also empties `@expiring`, so ending the
  page session drops any live code.
- Times are passed in explicitly; `ItemCache` never reads the wall clock, which
  keeps specs deterministic. The `Proxy` supplies `Time.utc` /
  `Time.utc +
  OTP_TTL`.

Between an entry's expiry and the next purge it may still be redacted —
harmless (it masks a now-invalid code) and removed at the next touchpoint.

### 4. Cleanup triggers (`Proxy`)

Global `purge_expired(Time.utc)` at the two touchpoints, no timer:

- `fetch_or_reveal(key)` — accessing an item directly (the secret-type path).
- `handle_find(finder, message)` — discovery / fetching all items.

### 5. Never cached (`ItemLocator#cache_value`)

Make non-caching explicit and robust:

```
OTP_TYPE = "OTP"
# ...
return nil if type == OTP_TYPE
```

Already effectively true (OTP is neither `CONCEALED` nor a username/password
purpose), but this states the intent and holds even if op ever tags an OTP
field as concealed. (`OTP_TYPE` constant shared/duplicated as fits the two call
sites; the plan will place it to avoid a cross-module dependency.)

### 6. Discoverability

OTP fields already appear in discovery with `type: "OTP"`. Update:

- `SecretTypeTool` definition `description`: note that one-time-password / TOTP
  fields are supported and their code is fetched live.
- `Proxy::INSTRUCTIONS`: one sentence that a TOTP field can be typed the same
  way and is resolved live (never cached).

## Security invariants (unchanged or strengthened)

- A live code is redacted and guarded while valid (added to the cache before
  use, purged after expiry / on `browser_close`).
- The code is never written to a durable field value, never on a command line
  (op prints it to stdout), and only fetched after the URL-authorization gate.
- No client-facing behavior change other than TOTP fields becoming typable.

## Testing

- `ItemLocator#one_time_password`: fake `op` returns a code for
  `item get <id> --vault <v> --otp` → assert the stripped value; empty/failed
  op → `ItemLocator::Error`.
- `ItemLocator#cache_value`: an `OTP` field reveals with a `nil` value
  (metadata only, not cached).
- `ItemCache`: `add_expiring_secret` → present in `each_plaintext`;
  `purge_expired(now)` with `now` after `expires_at` removes it, before it
  keeps it; `clear` drops it.
- `Proxy` secret call: OTP field → live fetch path → upstream `browser_type`
  receives the code; URL gate still enforced (unauthorized page → refusal, no
  op call); a previously-added expired code is purged on the next item access /
  discovery; failed-upstream log is redacted.

## Out of scope

- HOTP / counter-based or multiple-OTP-per-item handling.
- Reusing a cached code across calls within its window (each call fetches
  fresh; `op --otp` returns the same code within a period anyway).
- Configurable TTL or configurable caching policy.
