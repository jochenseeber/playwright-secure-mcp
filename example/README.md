# Example: Claude Code with playwright-secure-mcp

Launch config demonstrating Claude Code using this project's MCP server.

## Prerequisites

1. Build the binary from the repo root: `rake build`
2. Sign in to the 1Password CLI: `op signin`

## Launch

Run Claude Code from inside this directory so it picks up `.mcp.json`:

```bash
cd example
claude
```

The relative command path (`../bin/playwright-secure-mcp`) resolves against
this directory, so keep launching from here.

## Verify

In the session, run `/mcp` — the `playwright-secure` server should be listed.
