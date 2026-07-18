# Redact upstream stderr and exception logs (F3) — design

Date: 2026-07-18

## Goal

Fix security-review finding **F3**: two log sinks bypass the redaction gate, so
a cached secret can reach host logs even though it never reaches the MCP
client.

1. The upstream Playwright MCP child is started with
   `error:
   Process::Redirect::Inherit`, so anything it prints to stderr
   (e.g. under `DEBUG=pw:api`, which logs tool arguments including the typed
   value) goes straight to the proxy's inherited stderr, unredacted.
2. The catch-all handlers log the full exception object
   (`Log.error(exception: error)`), whose message could contain a cached
   secret.

Only `log_upstream_failure` currently redacts before logging. Everything
client-bound already goes through the redactor (`send_to_client`); this change
extends the same guarantee to the two log paths.

## Design

### 1. Upstream stderr: pipe, scrub, redact-and-log

`Upstream#start` changes:

- `error: Process::Redirect::Inherit` → `Process::Redirect::Pipe`.
- Scrub verbose-logging env vars from the child so it is less likely to print
  the secret at all: pass `env: {"DEBUG" => nil, "PWDEBUG" => nil}` (a `nil`
  value unsets the variable for the child; the rest of the environment is
  inherited).
- Expose the child's stderr: `Upstream#stderr : IO?` returning
  `@process.try(&.error)`.

New `StderrRedactor` (`src/playwright_secure_mcp/stderr_redactor.cr`):

```crystal
class StderrRedactor
  MAX_LINE = 8192

  def initialize(@io : IO, @redactor : Redactor, *, @log : ::Log = Log)
  end

  # Spawns a fiber that reads the upstream's stderr line by line (bounded per
  # line), redacts each line, and re-emits it, until EOF. Runs for the process
  # lifetime; the pipe MUST be drained or the child blocks once its buffer
  # fills.
  def start : Nil
    spawn do
      while line = @io.gets(MAX_LINE, chomp: true)
        next if line.empty?
        @log.warn { "upstream: #{@redactor.redact(line)}" }
      end
    rescue IO::Error
      # pipe closed on upstream exit; nothing more to read
    end
  end
end
```

`gets(MAX_LINE, chomp: true)` bounds each read to `MAX_LINE` chars or a
newline, so a pathological no-newline flood cannot allocate unboundedly.
`redactor.redact` is the existing string-leaf-safe redactor over arbitrary
text.

### 2. Exception logs: redact via the redactor

New `Redactor#redact_exception(error : Exception) : String`:

```crystal
def redact_exception(error : Exception) : String
  message = redact(error.message || "")
  backtrace = error.backtrace?.try(&.join("\n"))
  backtrace ? "#{error.class}: #{message}\n#{backtrace}" : "#{error.class}: #{message}"
end
```

- `error.class` and the backtrace frames (file:line) carry no secret values.
- `redact(error.message || "")` masks any cached secret in the message.

`Proxy` replaces the two catch-all logs:

```crystal
# handle_find rescue:
Log.error { "unexpected error handling #{finder.name}: #{@redactor.redact_exception(error)}" }
# handle_secret_call rescue:
Log.error { "unexpected error handling secret call: #{@redactor.redact_exception(error)}" }
```

The raw `exception: error` argument (which would print the unredacted message
and backtrace) is no longer passed. The client-bound `error_result` in these
rescues already passes through `send_to_client` → redactor, so it is unchanged.

### 3. Wiring (`Application`)

- Hoist `redactor = Redactor.new(cache)` into `run` and pass it into
  `build_proxy` (instead of constructing it inside).
- After `upstream_transport = upstream_process.start`, if
  `upstream_process.stderr` is non-nil,
  `StderrRedactor.new(stderr, redactor).start`. Do this before
  `build_proxy(...).run`.

## Files

- Modify: `src/playwright_secure_mcp/upstream.cr` — pipe stderr, scrub env,
  expose `stderr`.
- Create: `src/playwright_secure_mcp/stderr_redactor.cr`.
- Modify: `src/playwright_secure_mcp/redactor.cr` — add `redact_exception`.
- Modify: `src/playwright_secure_mcp/proxy.cr` — two catch-all logs use
  `redact_exception`.
- Modify: `src/playwright_secure_mcp/application.cr` — hoist redactor, start
  the stderr redactor.

## Behavior invariants

- No client-facing behavior change; only what reaches host logs changes.
- `op` stderr remains closed (already handled), secrets are still never on a
  command line, redaction of client output is untouched.
- Upstream diagnostics are preserved (redacted) rather than discarded.

## Honest limitation

Redaction is a denylist of the known cached secrets and their encodings.
Upstream stderr redaction catches a secret the upstream prints **verbatim** (or
in a known encoding); it cannot catch an arbitrary transform the upstream might
emit — the same limitation as F1. Scrubbing `DEBUG`/`PWDEBUG` reduces the
chance the secret is printed at all. This is a meaningful reduction of the
log-leak surface, not a proof of non-interference.

## Testing

- `StderrRedactor` (`spec/stderr_redactor_spec.cr`): feed an `IO::Memory` whose
  lines contain a cached secret; capture `Log` via `::Log::MemoryBackend`;
  assert the emitted entry contains `«REDACTED»` and not the secret; assert an
  over-`MAX_LINE` line is truncated (no unbounded allocation, still redacted).
- `Redactor#redact_exception` (`spec/redactor_spec.cr`): with a cached secret,
  an exception whose message contains it → result includes the class,
  `«REDACTED»`, and the backtrace frames, and does not include the raw secret.
  Construct the exception via `begin; raise; rescue e; e end` so it has a
  backtrace.
- `Upstream` (`spec/` if a test exists, else covered by build): starts the
  child with a piped, not inherited, stderr and the scrubbed env — verify by
  inspection/compile; a full subprocess test is out of scope.
- Existing specs stay green; `rake spec` / `rake lint` / `rake build` all
  green.

## Out of scope

- F1 (browser readback of a typed value) — separate finding.
- A configurable opt-in to keep upstream `DEBUG` or inherit raw stderr — can be
  added later; default is scrub + redact.
- Bounding total (vs per-line) stderr volume, or rate-limiting the log —
  per-line cap is sufficient for this fix; overall input bounding is F6.
