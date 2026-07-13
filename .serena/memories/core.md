# Core

Crystal MCP server that proxies the upstream Playwright MCP (`@playwright/mcp`, spawned as a stdio child) and injects secure 1Password secret handling. **Invariant: a resolved secret value never reaches the LLM.**

Entry: `src/main.cr` → `Application` (`application.cr`) wires config → cipher → vault → resolver → item locator → `Proxy`.

## Source map (`src/playwright_secure_mcp/`)
- **Proxy** (`proxy.cr`): the hub. Bridges client↔upstream JSON-RPC 2.0 over stdio; augments `tools/list` with secret tools; routes secret tool calls; redacts every client-bound message. Handlers run in fibers via `track`; `call_upstream` correlates injected requests by string id.
- **Secret tools**: `secret_finders.cr` (discovery: `browser_find_secret_by_{name,tag,url}` → return vault/item IDs only), `secret_type_tool.cr` (`browser_type_secret` → resolves + types), `secret_guard.cr` (rejects `op://`/raw secrets as args), `redactor.cr` (replaces secret + its url/base64/html/json variants with `«REDACTED»`).
- **1Password/op**: `op_runner.cr` (subprocess w/ 60s timeout), `item_locator.cr`, `secret_resolver.cr` (`op read`), `account_locator.cr`/`account_resolver.cr` (email→account UUID), `token_fetcher.cr` (service-account token).
- **Cipher tiers** (cache-key protection for `secret_vault.cr`): `cipher_selector.cr` → `secure_enclave_cipher.cr` (macOS Security FFI), `tpm_cipher.cr` (Linux TPM2/tss2 FFI), `keyring_cipher.cr`, `in_memory_cipher.cr`; `secret_cipher.cr`/`aes_cbc.cr`/`encrypted_secret.cr`.
- **Upstream mgmt**: `upstream.cr`, `upstream_command.cr`, `package_manager.cr` (pnpm/npm/none).
- Config: `command_line_parser.cr`, `configuration.cr`. Version: `version.cr` (reads `shard.yml` at compile time — single source of truth).

## Domain memories
- Stack/tooling: `mem:tech_stack`. Commands: `mem:suggested_commands`. Done-criteria: `mem:task_completion`.
- Code style/skills: `mem:conventions`.
- Rake/rakelib build+release architecture: `mem:build`.
- Hard-won gotchas (linker, codesign, op lock, MCP restart, proxy hangs): `mem:pitfalls`.
