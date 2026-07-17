# Encrypt the stored service-account token — design

Date: 2026-07-17

## Goal

Stop holding the 1Password service-account token as a long-lived plaintext
string. Encrypt it at rest under the process cipher and decrypt it only
transiently, for the duration of each `op` invocation that needs it. Addresses
the security-review finding that the token lived as a plaintext instance var
for the whole process lifetime.

## Current state

- `Application#run` fetches the token (plaintext `String` from `op`), passes it
  to `ItemLocator` as `service_account_token`, and also stores an encrypted
  copy in `ItemCache` via `add_loose_secret` (for redaction).
- `ItemLocator` keeps the plaintext in `@service_account_token : String?` for
  the process lifetime and reads it on every `op` call to set
  `OP_SERVICE_ACCOUNT_TOKEN`.

So the token exists both encrypted (redaction) and plaintext (op access). The
long-lived plaintext is the problem.

## Design

Store the token once, encrypted, in a dedicated `ItemCache` slot; decrypt only
inside a block that performs the `op` call. `ItemLocator` no longer holds any
plaintext.

### ItemCache

- New field `@service_token : EncryptedSecret? = nil`.
- `store_service_token(token : String) : Nil` —
  `@service_token =
  @cipher.encrypt(token.to_slice)`.
- `service_token? : Bool` — `!@service_token.nil?`.
- `with_service_token(& : String -> T) : T forall T` — decrypt the slot, yield
  the plaintext `String`, and zero the intermediate decrypted `Bytes` in an
  `ensure`. Raises if no token is set.

  ```crystal
  def with_service_token(& : String -> T) : T forall T
    entry = @service_token
    raise "no service-account token stored" if entry.nil?
    bytes = @cipher.decrypt(entry)
    begin
      yield String.new(bytes)
    ensure
      bytes.fill(0_u8)
    end
  end
  ```

- `collect_entries` (used by `each_plaintext`/`each_ciphertext_for_test`) also
  includes `@service_token` when present, so the redactor and guard still cover
  the token.
- `clear` is unchanged (clears `@items` only) — the service token survives
  `browser_close`, so continued `op` access works, matching today's
  loose-secret retention.
- `add_loose_secret`/`@loose` stay (still used by specs); the token stops being
  a loose secret and uses the dedicated slot instead.

### ItemLocator

- Drop the `service_account_token : String?` constructor parameter and the
  `@service_account_token` instance var. Keep `@account` and `@encryptor`.
- `run` chooses auth by asking the cache:

  ```crystal
  private def run(arguments, *, vault, input = nil) : String
    argv = arguments.dup
    argv << "--vault" << vault if vault
    if @encryptor.service_token?
      @encryptor.with_service_token do |token|
        invoke(argv, env: {"OP_SERVICE_ACCOUNT_TOKEN" => token.as(String?)}, input: input, arguments: arguments)
      end
    else
      argv << "--account" << @account.as(String) if @account
      invoke(argv, env: nil, input: input, arguments: arguments)
    end
  end
  ```

  `invoke` holds the existing `OpRunner.run` + timeout/exit-status handling and
  returns the output string. The op call runs **inside** the block, so the
  token plaintext is alive only for that call.

### Application

- Fetch the token as today; then `cache.store_service_token(token)` (replacing
  `add_loose_secret(token)`).
- Construct `ItemLocator` with `account: account` always (no
  `service_account_token:`); the locator decides env-vs-`--account` via
  `service_token?`.
- The startup plaintext `token` local is unreferenced after
  `store_service_token` and becomes GC-eligible.

## Behavior invariants

- `op` invocation identical: `OP_SERVICE_ACCOUNT_TOKEN` set (and `--account`
  omitted) when a token is configured; `--account` used otherwise.
- Token still redacted from all client-bound output and rejected by the guard.
- No behavior change to items, discovery, typing, or URL binding.

## Honest limitation

Crystal `String`s are immutable and GC-managed, so the decrypted plaintext
`String` (and the env string handed to `op`) cannot be zeroed — only the
intermediate `Bytes` are. The improvement is the removal of the long-lived
plaintext: the token is encrypted at rest for the process lifetime and
decrypted only per `op` call. The `op` child still receives it via the
environment, which is inherent to `OP_SERVICE_ACCOUNT_TOKEN`.

## Testing

- `ItemCache`: `store_service_token` + `with_service_token` round-trip;
  `service_token?` false→true; token retained after `clear`; token appears in
  `each_plaintext`; ciphertext never contains the plaintext;
  `with_service_token` raises when none stored.
- `ItemLocator`: with a token stored in the cache, `op` is invoked with
  `OP_SERVICE_ACCOUNT_TOKEN` and without `--account` (the existing token test,
  updated to set the token via `cache.store_service_token` instead of the
  removed constructor param); without a token, `--account` is passed.
- Existing specs stay green; `rake spec`/`rake lint`/`rake build` all green.

## Scope / rollout

One compile-safe milestone: `ItemCache` + `ItemLocator` + `Application` change
together (the `ItemLocator` constructor signature changes, so its only
constructor call site in `Application` updates in the same commit).
Conventional `refactor:`-or-`feat:` commit; behavior-preserving, so
`refactor:`.

## Out of scope

- Passing the token to `op` by a mechanism other than the environment.
- Zeroing immutable plaintext strings (not possible in Crystal).
- Any change to item caching, redaction structure, or URL binding.
