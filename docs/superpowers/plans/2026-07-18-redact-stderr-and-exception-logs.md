# Redact upstream stderr and exception logs (F3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close F3 — route the two remaining log sinks (upstream child stderr and
catch-all exception logs) through the redactor so a cached secret can't reach
host logs.

**Architecture:** Pipe the upstream child's stderr (instead of inheriting it) and
drain it through a redacting reader fiber; scrub `DEBUG`/`PWDEBUG` from the child;
add `Redactor#redact_exception` and use it in the proxy's catch-all logs.

**Tech Stack:** Crystal ≥ 1.20 (`Process`, `Log`, fibers), Spectator specs.

## Global Constraints

- Crystal `>= 1.20`; edit with Write/Edit (never Serena symbol editing).
- No client-facing behavior change; only host-log content changes. Redaction of
  client output, `op` stderr handling (already closed), and no-secret-on-argv are
  untouched.
- Every new/modified file requires its own direct dependencies; no include-all.
- `rake spec` / `rake lint` / `rake build` all green.
- Commit: Conventional `fix:` (security fix), body an unordered bullet list ≤72
  cols, no AI/Claude/Copilot references. ONE commit (compile-safe unit).
- Ad-hoc `crystal spec` needs `--link-flags=-fuse-ld=/usr/bin/ld`; rake handles
  it.

All five tasks below land in a single commit (Task 3 pipes stderr and Task 5
drains it — they must ship together so the child never blocks on a full pipe).

---

### Task 1: `Redactor#redact_exception`

**Files:**
- Modify: `src/playwright_secure_mcp/redactor.cr`
- Test: `spec/redactor_spec.cr`

**Interfaces produced:** `Redactor#redact_exception(error : Exception) : String`.

- [ ] **Step 1: Failing test** (append inside the existing describe block)

```crystal
  it "redacts a cached secret in an exception message, keeping class and backtrace" do
    cache.add_loose_secret("hunter2")
    error =
      begin
        raise "login failed for token=hunter2"
      rescue caught
        caught
      end
    result = redactor.redact_exception(error)
    expect(result.includes?("«REDACTED»")).to be_true
    expect(result.includes?("hunter2")).to be_false
    expect(result.includes?("Exception")).to be_true      # the class
    expect(result.includes?("spec/redactor_spec.cr")).to be_true  # a backtrace frame
  end
```

(The `let(cache)` / `let(redactor)` in `spec/redactor_spec.cr` already build a
cache + redactor; `add_loose_secret` adds a redactable secret.)

- [ ] **Step 2: Run — FAIL**

Run: `crystal spec spec/redactor_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: FAIL (`redact_exception` undefined).

- [ ] **Step 3: Implement** — add to `redactor.cr` after the `redact(text : String)`
  method:

```crystal
    # Formats an exception for a log line with any cached secret in its message
    # masked. The class name and backtrace frames (file:line) carry no secret
    # values; only the message is redacted.
    def redact_exception(error : Exception) : String
      message = redact(error.message || "")
      backtrace = error.backtrace?.try(&.join("\n"))
      if backtrace
        "#{error.class}: #{message}\n#{backtrace}"
      else
        "#{error.class}: #{message}"
      end
    end
```

- [ ] **Step 4: Run — PASS**

Run: `crystal spec spec/redactor_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS.

### Task 2: `StderrRedactor`

**Files:**
- Create: `src/playwright_secure_mcp/stderr_redactor.cr`
- Test: `spec/stderr_redactor_spec.cr`

**Interfaces produced:** `StderrRedactor.new(io : IO, redactor : Redactor, *,
log : ::Log = Log)`, `#start : Nil`.

- [ ] **Step 1: Failing test**

```crystal
# spec/stderr_redactor_spec.cr
require "./spec_helper"
require "../src/playwright_secure_mcp/item_cache"
require "../src/playwright_secure_mcp/redactor"
require "../src/playwright_secure_mcp/stderr_redactor"

Spectator.describe PlaywrightSecureMcp::StderrRedactor do
  let(cache) do
    c = PlaywrightSecureMcp::ItemCache.new
    c.add_loose_secret("s3cr3t")
    c
  end
  let(redactor) { PlaywrightSecureMcp::Redactor.new(cache) }

  private def drain(io : IO) : Array(String)
    backend = ::Log::MemoryBackend.new
    log = ::Log.new("test", backend, :debug)
    PlaywrightSecureMcp::StderrRedactor.new(io, redactor, log: log).start
    10.times { break unless backend.entries.empty?; Fiber.yield }
    backend.entries.map(&.message)
  end

  it "redacts a cached secret in an upstream stderr line" do
    messages = drain(IO::Memory.new("pw:api browser_type text=s3cr3t\n"))
    expect(messages.any?(&.includes?("«REDACTED»"))).to be_true
    expect(messages.any?(&.includes?("s3cr3t"))).to be_false
  end

  it "bounds an over-long line" do
    messages = drain(IO::Memory.new("x" * 20_000))
    expect(messages.first?.try(&.size).not_nil! <= PlaywrightSecureMcp::StderrRedactor::MAX_LINE + 64).to be_true
  end
end
```

- [ ] **Step 2: Run — FAIL** (undefined).

- [ ] **Step 3: Create `src/playwright_secure_mcp/stderr_redactor.cr`**

```crystal
require "log"
require "./redactor"

module PlaywrightSecureMcp
  # Drains an upstream child's stderr through the redactor and re-emits it via
  # Log, so a secret the upstream prints (e.g. under DEBUG) does not reach host
  # logs verbatim. Reads are bounded per line.
  class StderrRedactor
    Log = ::Log.for(self)

    MAX_LINE = 8192

    def initialize(@io : IO, @redactor : Redactor, *, @log : ::Log = Log)
    end

    def start : Nil
      spawn do
        while line = @io.gets(MAX_LINE, chomp: true)
          next if line.empty?
          redacted = @redactor.redact(line)
          @log.warn { "upstream: #{redacted}" }
        end
      rescue IO::Error
        # Pipe closed on upstream exit; nothing more to read.
      end
    end
  end
end
```

- [ ] **Step 4: Run — PASS**

Run: `crystal spec spec/stderr_redactor_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS.

### Task 3: `Upstream` pipes + scrubs stderr

**Files:** Modify `src/playwright_secure_mcp/upstream.cr`.

**Interfaces produced:** `Upstream#stderr : IO?`. `start` signature unchanged.

- [ ] **Step 1: Modify `start` and add `stderr`**

```crystal
    def start : StdioTransport
      raise Error.new("upstream command is empty") if @tokens.empty?
      process = Process.new(
        @tokens.first,
        @tokens[1..],
        # Scrub verbose-logging vars so the child does not print typed values.
        env: {"DEBUG" => nil, "PWDEBUG" => nil},
        input: Process::Redirect::Pipe,
        output: Process::Redirect::Pipe,
        error: Process::Redirect::Pipe,
      )
      @process = process
      StdioTransport.new(input: process.output, output: process.input)
    end

    # The upstream child's stderr pipe (only after start). Callers MUST drain it
    # or the child blocks once its stderr buffer fills.
    def stderr : IO?
      @process.try(&.error)
    end
```

(`env:` with `nil` values unsets those variables for the child while inheriting
the rest of the environment. `Process#error` is the readable pipe when
`error: Pipe`.)

- [ ] **Step 2: Compile check** — `rake build` still compiles (Application does not
  yet call `stderr`; behavior verified in the full suite at Task 5).

### Task 4: `Proxy` catch-all logs use `redact_exception`

**Files:** Modify `src/playwright_secure_mcp/proxy.cr`.

- [ ] **Step 1:** Replace the two catch-all logs. In `handle_find`'s `rescue error
  : Exception`:

```crystal
      Log.error { "unexpected error handling #{finder.name}: #{@redactor.redact_exception(error)}" }
```

In `handle_secret_call`'s `rescue error : Exception`:

```crystal
      Log.error { "unexpected error handling secret call: #{@redactor.redact_exception(error)}" }
```

(Delete the `exception: error` argument in both; keep the `send_to_client(
error_result(...))` line that already redacts via `send_to_client`.)

- [ ] **Step 2: Compile** — `rake build`.

### Task 5: `Application` wiring

**Files:** Modify `src/playwright_secure_mcp/application.cr`.

- [ ] **Step 1:** Add `require "./stderr_redactor"` at the top. Hoist the redactor
  and start the stderr redactor. In `run`, replace the upstream/proxy section:

```crystal
      redactor = Redactor.new(cache)
      tokens = UpstreamCommand.new(configuration).tokens
      upstream_process = Upstream.new(tokens)
      upstream_transport = upstream_process.start
      if stderr = upstream_process.stderr
        StderrRedactor.new(stderr, redactor).start
      end
      begin
        build_proxy(upstream_transport, cache: cache, item_locator: item_locator, redactor: redactor).run
      ensure
        upstream_process.stop
      end
```

Change `build_proxy` to accept the redactor instead of constructing it:

```crystal
    private def build_proxy(upstream_transport : StdioTransport, *, cache : ItemCache, item_locator : ItemLocator, redactor : Redactor) : Proxy
      # ... finders unchanged ...
      Proxy.new(
        # ... unchanged args ...
        redactor: redactor,
        # ... unchanged args ...
      )
    end
```

(Delete the `redactor: Redactor.new(cache)` line inside `build_proxy`.)

- [ ] **Step 2: Milestone gate + commit**

Run: `rake spec && rake lint && rake build`
Expected: all green.

```bash
git add src/playwright_secure_mcp/redactor.cr spec/redactor_spec.cr \
        src/playwright_secure_mcp/stderr_redactor.cr spec/stderr_redactor_spec.cr \
        src/playwright_secure_mcp/upstream.cr src/playwright_secure_mcp/proxy.cr \
        src/playwright_secure_mcp/application.cr src/playwright_secure_mcp.cr
git commit  # fix: redact upstream stderr and exception logs  (+ bullet body)
```

(If `src/playwright_secure_mcp.cr` has an include-all list, it does not — each
file requires its deps directly; the new `stderr_redactor` is required by
`application.cr`. Do not add it to any aggregator.)

---

## Self-review notes

- **Spec coverage:** upstream stderr pipe+scrub (Task 3) + drain/redact (Task 2
  + Task 5), exception redaction (Task 1 + Task 4), wiring (Task 5). All covered.
- **Type consistency:** `Redactor#redact_exception(Exception) : String`;
  `StderrRedactor.new(IO, Redactor, *, log)`; `Upstream#stderr : IO?`;
  `build_proxy(..., redactor : Redactor)`. Names match across tasks.
- **Runtime safety:** stderr is piped (Task 3) and drained (Task 5) in the same
  commit, so the child never blocks; `StderrRedactor` bounds each read.
- **No placeholders:** all steps carry concrete code/commands.
