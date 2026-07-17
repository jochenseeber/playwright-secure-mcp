# Encrypt the service-account token — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hold the 1Password service-account token only encrypted at rest, and
decrypt it transiently inside each `op` call — no long-lived plaintext instance
var.

**Architecture:** A dedicated encrypted slot in `ItemCache` holds the token;
`ItemLocator` asks the cache for it via a `with_service_token` block that
scopes the plaintext to the op call; `Application` stores it once at startup.

**Tech Stack:** Crystal ≥ 1.20, existing `SecretCipher` (Secure Enclave / TPM /
keyring / in-memory), Spectator specs.

## Global Constraints

- Crystal `>= 1.20`; edit with Write/Edit (never Serena symbol editing).
- Behavior of `op` invocation unchanged: `OP_SERVICE_ACCOUNT_TOKEN` set and
  `--account` omitted when a token is configured; `--account` otherwise.
- Token stays in the redactor/guard set (`ItemCache#each_plaintext`) and
  survives `clear`/`browser_close`.
- No plaintext token retained beyond a single `op` call; zero the decrypted
  `Bytes` in an `ensure` (the immutable plaintext `String` cannot be zeroed —
  documented limitation).
- Each file requires its direct deps; `op` only via `OpRunner.run`; no secret
  on a command line.
- `rake spec`/`rake lint`/`rake build` green before commit.
- Commit: Conventional `refactor:`, body an unordered bullet list ≤72 cols, no
  AI/Claude/Copilot references. ONE commit (compile-safe unit).
- Ad-hoc `crystal spec`/`run` needs `--link-flags=-fuse-ld=/usr/bin/ld`; rake
  handles it.

---

## Task 1: ItemCache service-token slot

**Files:**

- Modify: `src/playwright_secure_mcp/item_cache.cr`
- Test: `spec/item_cache_spec.cr`

**Interfaces produced:** `#store_service_token(token : String) : Nil`,
`#service_token? : Bool`, `#with_service_token(& : String -> T) : T forall T`;
`each_plaintext`/`each_ciphertext_for_test` now include the token.

- [ ] **Step 1: Write the failing tests** (append to `spec/item_cache_spec.cr`)

```crystal
  it "round-trips the service token and reports presence" do
    expect(cache.service_token?).to be_false
    cache.store_service_token("ops_tok_123")
    expect(cache.service_token?).to be_true
    seen = nil.as(String?)
    cache.with_service_token { |t| seen = t }
    expect(seen).to eq("ops_tok_123")
  end

  it "keeps the service token across clear and in each_plaintext" do
    cache.store_service_token("ops_tok_123")
    cache.clear
    expect(cache.service_token?).to be_true
    collected = [] of String
    cache.each_plaintext { |s| collected << s }
    expect(collected.includes?("ops_tok_123")).to be_true
  end

  it "does not keep the service token plaintext in ciphertext" do
    cache.store_service_token("ops_tok_123")
    dumped = [] of String
    cache.each_ciphertext_for_test { |b| dumped << b.hexstring }
    expect(dumped.join.includes?("ops_tok_123".to_slice.hexstring)).to be_false
  end

  it "raises when with_service_token is called with none stored" do
    expect { cache.with_service_token { |_| } }.to raise_error(Exception)
  end
```

(`let(cache) { PlaywrightSecureMcp::ItemCache.new }` already exists in the
file.)

- [ ] **Step 2: Run — FAIL**

Run: `crystal spec spec/item_cache_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: FAIL (`store_service_token`/`service_token?`/`with_service_token`
undefined).

- [ ] **Step 3: Implement in `item_cache.cr`**

Add `@service_token : EncryptedSecret? = nil` to `initialize`. Add the methods:

```crystal
    def store_service_token(token : String) : Nil
      @service_token = @cipher.encrypt(token.to_slice)
    end

    def service_token? : Bool
      !@service_token.nil?
    end

    # Decrypts the service token for the duration of the block, zeroing the
    # decrypted bytes afterward. Raises if no token is stored.
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

Include the token in `collect_entries` so redaction/guard cover it:

```crystal
private def collect_entries : Array(EncryptedSecret)
  entries = [] of EncryptedSecret
  @items.each_value do |item|
    item.fields.each_value do |field|
      value = field.value
      entries << value unless value.nil?
    end
  end
  entries.concat(@loose)
  token = @service_token
  entries << token unless token.nil?
  entries
end
```

(`clear` unchanged — clears `@items` only, so the token persists.)

- [ ] **Step 4: Run — PASS**

Run: `crystal spec spec/item_cache_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS.

- [ ] **Step 5:** Fold into the single commit; proceed to Task 2.

## Task 2: ItemLocator decrypts per op call

**Files:**

- Modify: `src/playwright_secure_mcp/item_locator.cr`
- Test: `spec/item_locator_spec.cr`

**Interface change:** `ItemLocator.new` drops the `service_account_token`
parameter (keeps `op_command`, `account`, `encryptor`).

- [ ] **Step 1: Update the token test** in `spec/item_locator_spec.cr`

If a test constructs `ItemLocator.new(..., service_account_token: "tok")` and
asserts env-token behavior, change it to store the token in the cache instead:

```crystal
it "passes the service token via the environment and omits --account" do
  cache.store_service_token("tok")
  token_locator = PlaywrightSecureMcp::ItemLocator.new(
    op_command: FAKE_OP_ITEMS, account: "acct1", encryptor: cache)
  # fake op returns the login only when OP_SERVICE_ACCOUNT_TOKEN is set and
  # --account is absent (see fixture); assert a successful reveal/list.
  items = token_locator.list_logins(nil)
  expect(items.empty?).to be_false
end
```

Confirm the `fake_op_items` fixture's list branch already keys on
`OP_SERVICE_ACCOUNT_TOKEN` / absence of `--account`; if not, add a branch so
the assertion is meaningful. (If the current spec has no token test, add the
one above.)

- [ ] **Step 2: Run — FAIL** (constructor still requires
      `service_account_token` or the env path not wired).

- [ ] **Step 3: Rewrite the constructor + `run` in `item_locator.cr`**

```crystal
def initialize(*, @op_command : String, @account : String?, @encryptor : ItemCache)
end
```

Replace `run` with a token-aware version that runs op inside the decrypt block:

```crystal
    private def run(arguments : Array(String), *, vault : String?, input : String? = nil) : String
      argv = arguments.dup
      argv << "--vault" << vault if vault
      if @encryptor.service_token?
        @encryptor.with_service_token do |token|
          invoke(arguments, argv, {"OP_SERVICE_ACCOUNT_TOKEN" => token.as(String?)}, input)
        end
      else
        argv << "--account" << @account.as(String) if @account
        invoke(arguments, argv, nil, input)
      end
    end

    private def invoke(arguments : Array(String), argv : Array(String), env : Process::Env, input : String?) : String
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
```

(Removes the `@service_account_token` field and its env branch. `Process::Env`
is `Hash(String, String?)?`; the literal matches the old code's type.)

- [ ] **Step 4: Run — PASS**

Run: `crystal spec spec/item_locator_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS.

## Task 3: Application wiring

**Files:**

- Modify: `src/playwright_secure_mcp/application.cr`

- [ ] **Step 1: Update `run`**

Replace the token storage + locator construction:

```crystal
token = fetch_token(configuration, account)
cache.store_service_token(token) if token
item_locator = ItemLocator.new(
  op_command: configuration.op_command,
  account: account,
  encryptor: cache,
)
```

Delete the `cache.add_loose_secret(token) if token && !token.empty?` line and
the `service_account_token: token` / `account: token ? nil : account`
arguments. Keep `fetch_token` as-is.

- [ ] **Step 2: Milestone gate**

Run: `rake spec && rake lint && rake build` Expected: all green (no leftover
`service_account_token` / `add_loose_secret(token)` references — grep to
confirm).

- [ ] **Step 3: Commit**

```bash
git add src/playwright_secure_mcp/item_cache.cr src/playwright_secure_mcp/item_locator.cr \
        src/playwright_secure_mcp/application.cr spec/item_cache_spec.cr spec/item_locator_spec.cr
git commit  # refactor: hold the service-account token encrypted, decrypt per op call  (+ bullet body)
```

---

## Self-review notes

- **Spec coverage:** encrypted slot + transient decrypt (Task 1), no plaintext
  field in ItemLocator + op-inside-block (Task 2), application stores once
  (Task 3), redaction retention + clear survival (Task 1 tests), behavior
  invariance (item_locator token test). Covered.
- **Type consistency:**
  `store_service_token`/`service_token?`/`with_service_token` used by
  ItemLocator#run; `invoke` carries the old OpRunner/timeout/status logic;
  `Process::Env` type preserved.
- **Compile safety:** ItemLocator's constructor signature changes and its only
  call site (Application) changes in the same commit; no other caller.
