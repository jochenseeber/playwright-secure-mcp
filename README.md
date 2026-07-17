# playwright-secure-mcp

A Crystal MCP server that transparently proxies the upstream
[Playwright MCP server](https://github.com/microsoft/playwright-mcp)
(`@playwright/mcp`) and adds secure password handling. Its goal: **a resolved
secret value never reaches the LLM.**

## How it works

- The binary speaks MCP JSON-RPC 2.0 over stdio to the client (the LLM host)
  and spawns `@playwright/mcp` as a stdio child process, forwarding nearly all
  messages untouched.
- It adds four secret tools to the upstream `tools/list`: three discovery tools
  that list or find 1Password LOGIN items usable on the current browser page,
  and `browser_type_secret`, which types a field of a chosen item into the
  page. Closing the browser (`browser_close`) empties the local item cache. See
  [Secret tools](#secret-tools).
- Every message flowing back to the client is passed through a redactor that
  replaces each resolved secret — including its URL-encoded, Base64,
  HTML-escaped, and JSON-escaped variants — with the literal token
  `«REDACTED»`. Secrets are caught wherever they appear: page snapshots,
  network request dumps, console messages, and error text.

## Secret tools

### Discovery: list or find items for the current page

Three tools look up 1Password LOGIN items and return only those usable on the
current browser page: the proxy reads the page's `location.href` itself (the
caller never supplies a URL) and keeps an item only when one of its URLs
matches the page by host and path prefix. If the current URL cannot be
determined, discovery fails with an error. Results are a JSON array of item
identities plus non-secret field metadata — `vault`, `item`, `title`, `urls`,
`tags`, `fields` (id, label, type, purpose, section), and `sections` — never a
field value. All three accept an optional `vault` (ID or name) to scope the
search.

| Tool                         | Required arguments   | Result                                               |
| ---------------------------- | -------------------- | ---------------------------------------------------- |
| `browser_list_items`         | _(none)_             | All LOGIN items usable on the current page           |
| `browser_find_items_by_name` | `item` (title or ID) | Matching items, filtered to the current page         |
| `browser_find_items_by_tag`  | `tag`                | Items carrying the tag, filtered to the current page |

### Typing: `browser_type_secret`

Mirrors the upstream `browser_type` tool, but instead of a literal `text` value
it takes the 1Password coordinates of the secret:

- Required: `element`, `ref` (as in `browser_type`), `vault` (1Password vault
  ID), `item` (1Password item ID), `field` (e.g. `username` or `password`)
- Optional: `submit`, `slowly` (as in `browser_type`)

The proxy resolves the field from the cached item (fetching the item from
1Password on demand when it is not cached), decrypts the value locally, and
issues an internal `browser_type` call to the upstream server with the resolved
value. Typing is refused unless the current page is in the item's URL set (the
same host + path-prefix match as discovery), and refused when the current page
URL cannot be determined.

### Cache lifetime

Discovered items — with their field values encrypted — are cached in memory,
write-once. Calling the upstream `browser_close` tool empties this cache (the
close is still forwarded to the browser as usual); otherwise it lives for the
process lifetime.

### Workflow: find, then type

1. Navigate to the login page, then call a discovery tool — e.g.
   `browser_list_items` — to obtain the `vault` and `item` IDs of an item
   usable on that page.
2. Call `browser_type_secret` with those IDs and the `field` to type.

## Install

### Homebrew (macOS and Linux)

Install from the Homebrew tap. The formula installs the prebuilt binary from
the latest GitHub release (the macOS builds are signed and notarized):

```bash
brew install jochenseeber/tap/playwright-secure-mcp
```

This puts `playwright-secure-mcp` on your `PATH`. It still needs the 1Password
CLI (`op`) and a Playwright MCP server — see [Requirements](#requirements).

To build from source instead, see [Build](#build).

## Requirements

- Crystal `>= 1.20`
- The 1Password CLI (`op`), signed in
- `pnpm` or `npm` to download `@playwright/mcp` on demand, or a pre-installed
  Playwright MCP server binary

## Build

```bash
rake setup
rake build
```

`rake build` writes a debug binary to
`bin/<profile>-<mode>/playwright-secure-mcp` (e.g.
`bin/darwin-arm64-system-dynamic-debug/…`) and a `bin/playwright-secure-mcp`
symlink to the latest build. Use `rake "build[release]"` for a release binary.
Run `rake -T` to list all available tasks.

## Options

| Option                   | Default                 | Meaning                                                                   |
| ------------------------ | ----------------------- | ------------------------------------------------------------------------- |
| `--package-manager`      | `pnpm`                  | `pnpm` (`pnpm dlx`), `npm` (`npx -y`), or `none` (pre-installed)          |
| `--mcp-version`          | `latest`                | `@playwright/mcp` version tag/range (ignored when `none`)                 |
| `--mcp-bin`              | `mcp-server-playwright` | Pre-installed binary; implies `--package-manager none`                    |
| `--command`              | _(none)_                | Explicit upstream command override                                        |
| `--op-command`           | `op`                    | 1Password CLI binary                                                      |
| `--account-from-git`     | _(none)_                | Read the account email from `DIR/.git/config` (`user.email`)              |
| `--account`              | _(none)_                | 1Password account (shorthand, sign-in email, or account ID)               |
| `--account-email`        | _(none)_                | 1Password account email                                                   |
| `--token-tag`            | _(none)_                | 1Password item tag whose `credential` field holds a service-account token |
| `--require-hardware-key` | _(off)_                 | Refuse to start without Secure Enclave/TPM key protection                 |
| `--version`              | _(none)_                | Print the version and exit                                                |
| `-- <args...>`           | _(none)_                | Extra args forwarded to the upstream server                               |

The three account options resolve to a single account passed to `op` via
`--account`; when more than one is given, precedence is `--account-from-git` >
`--account-email` > `--account`. With `--token-tag`, the resolved account is
used once at startup (interactive `op`) to fetch the tagged item's `credential`
field, and that value is then used as `OP_SERVICE_ACCOUNT_TOKEN` for all
subsequent secret resolution — in that mode `--account` is not passed to
`op read`. Without `--token-tag`, each `op read` uses the resolved account
directly.

## MCP client configuration

```json
{
    "mcpServers": {
        "playwright": {
            "command": "/path/to/bin/playwright-secure-mcp",
            "args": ["--", "--headless"]
        }
    }
}
```

## Security model

- The resolved secret travels `op` → this process → upstream child → browser.
  It is never present in anything the LLM sent, and never present un-redacted
  in anything the LLM receives.
- Revealed items are cached in-memory for the process lifetime (or until the
  browser is closed via `browser_close`) in an obfuscated vault: each field
  value is AES-256-CBC encrypted under a random per-process data key with a
  fresh random IV per entry. The data key itself is hardware-protected when
  possible — see [Cache key protection](#cache-key-protection).
- **Caveat:** the vault is obfuscation / defense-in-depth, not a security
  boundary. With the in-memory fallback tier the encryption key lives in the
  same process memory as the ciphertext, so it defeats casual heap inspection,
  `strings`-style scanning, and accidental plaintext logging — but not an
  attacker with full process-memory access. A hardware-backed tier removes the
  long-lived key from process memory, but see the limitations below.

## Cache key protection

At startup the proxy picks the best available protection tier for the vault's
AES-256 data key and logs the choice:

1. **Secure Enclave** (macOS, hardware): an ephemeral, non-extractable P-256
   key is generated inside the Secure Enclave, and the data key is
   ECIES-wrapped under it. The wrapped key is unwrapped in the enclave per
   crypto batch and the plaintext key is zeroed afterwards; the long-lived key
   never exists in process memory or on disk.
2. **TPM 2.0** (Linux, hardware): the data key is sealed inside the platform
   TPM via the tpm2-tss ESYS library over `/dev/tpmrm0` and unsealed
   transiently per crypto batch, then zeroed. The binary links tpm2-tss, which
   is assumed present on the host.
3. **Kernel keyring** (Linux, **not** hardware): the data key is stored in the
   kernel keyring and AES runs in the kernel via an AF_ALG socket, so the key
   never re-enters process memory — but it is kernel-backed, not
   hardware-backed. Requires Linux ≥ 5.4.
4. **In-memory** (fallback): a plain per-process key, with a startup warning
   that hardware-backed protection is unavailable.

On Linux the order is TPM → keyring → in-memory. Pass `--require-hardware-key`
to fail closed: the proxy refuses to start unless a hardware-backed tier
(Secure Enclave / TPM) initializes. The kernel keyring tier does **not**
satisfy `--require-hardware-key`.

**Deployment requirement (macOS):** the Secure Enclave is only usable when the
distributed binary is **code-signed with the appropriate entitlement** (Secure
Enclave / keychain access). An unsigned binary cannot generate an enclave key
(Security.framework fails with OSStatus -26276) and falls back to the
in-process key — or refuses to start under `--require-hardware-key`.

Limitations:

- The unwrapped data key is in process memory transiently per crypto batch,
  then best-effort zeroed.
- Decrypted secret plaintext still transits process memory during redaction and
  typing (out of scope; would require a sidecar).
- Per-message hot-path cost with the Secure Enclave is ~2–20 ms (one key unwrap
  per message batch).

## Tests

```bash
rake spec
rake lint
```
