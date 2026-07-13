# Task Completion

Run before considering a change done:

1. `rake spec` — Spectator unit suite, expect 0 failures.
2. `rake lint` — Ameba, fix all warnings (required before commit).
3. If Ruby build files (`rakelib/`, `Rakefile`) changed: `bundle exec rubocop rakelib Rakefile`.
4. If runtime source changed: `rake build` (must succeed + codesign).

## Verifying runtime behavior via the MCP server
- The `playwright-secure` MCP server runs the **compiled** `bin/playwright-secure-mcp`. After `rake build`, a `/mcp reconnect` is NOT enough — it keeps the stale binary. Fully restart the MCP server process to load new code (see `mem:pitfalls`).
- `op` must be unlocked for any secret-reveal path to work (see `mem:pitfalls`).

## VCS
- Do not commit/tag unless explicitly asked (user rule). `rake release` performs commits/tags by design when the user runs it.
