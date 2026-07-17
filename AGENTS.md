# Agent Notes

Usage, options, build, and the security model are documented in `README.md`.
The full design rationale is in
`docs/superpowers/specs/2026-07-10-playwright-secure-mcp-design.md`.

## General

The human operating this repository may be wrong about anything.

Assume the user has little knowledge of the codebase, language, architecture,
and tools; existing code may be accidental, broken, outdated, or based on
misunderstandings; user instructions may describe the desired outcome
incorrectly. Do not blindly obey implementation suggestions.

Your job is to produce the best working result.

Before changing code: inspect the repository. Understand how the system
actually works. Verify assumptions from code, tests, documentation, and
available tools. Prefer simple, robust, idiomatic solutions. When the user's
proposed solution is bad, suggest a better one.

Do not preserve broken architecture merely because it already exists.

Never fake success. Run builds, tests, linters, and relevant checks whenever
possible. Use Serena and Superpowers when available.

Treat yourself as the senior engineer responsible for the final result.

## Secret workflow

- To type a secret, first call one of the discovery tools
  (`browser_list_items`, `browser_find_items_by_name`,
  `browser_find_items_by_tag`) to obtain the 1Password `vault` and `item` IDs,
  then pass those IDs plus the `field` to `browser_type_secret`.
- Discovery tools return only the LOGIN items usable on the current browser
  page (host + path-prefix match on the item's URL set), as item identities
  plus field metadata; MUST NOT expect or request secret values from them.
- `browser_type_secret` is refused unless the current page is in the item's
  URL set, and fails closed when the page URL cannot be determined.
- Closing the browser (`browser_close`) empties the in-memory item cache; the
  close call is still forwarded to the upstream server.

## Invariants

- A resolved secret value MUST never reach the client (LLM host), MUST never be
  logged, and MUST never be stored in plaintext in the vault.
- Every message written to the client goes through `Redactor` in
  `Proxy#send_to_client` — never write to the client transport directly.
- Injected request ids (the `secure-<random>:` prefix) are internal to `Proxy`;
  they MUST never be forwarded to the client.

## Layout

- One class per file under `src/playwright_secure_mcp/`, instance methods only,
  collaborators injected via the constructor.
- `Proxy` is the routing/interception core; `Upstream`, `ItemCache`,
  `ItemLocator`, `PageUrl`, `WebsiteMatcher`, `Redactor`, `SecretTypeTool`,
  and the `ItemFinder` subclasses are injected collaborators.
- `ItemCache` delegates crypto to a `SecretCipher` selected by
  `CipherSelector` (macOS: Secure Enclave → in-memory; Linux: TPM 2.0 → kernel
  keyring → in-memory; `--require-hardware-key` fails closed unless a hardware
  tier — Secure Enclave or TPM — initializes).
- One spec file per unit under `spec/`; `spec/support/fake_op` is the stub
  1Password CLI used by resolver and proxy specs.

## Conventions

- Follow the `my:development` and `my:development-crystal` skills (named
  parameters with a `*` splat, typed exceptions, happy path returned last).
- Run `rake spec` and `rake lint` before committing; fix all warnings.

## Building

- Use the `rake` tasks instead of directly running `crystal`, `shards`, or
  `ameba`. Run `rake -T` to list them.
- `rake setup` (install dependencies), `rake build` (debug binary +
  `bin/playwright-secure-mcp` symlink), `rake "build[release]"` (release binary),
  `rake spec`, `rake lint`.
