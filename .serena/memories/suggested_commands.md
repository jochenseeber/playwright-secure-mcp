# Suggested Commands

Always prefer `rake` over raw `crystal`/`shards` (the Rakefile injects the macOS linker workaround — see `mem:pitfalls`).

- `rake setup` / `rake deps` — `shards install`.
- `rake build` — debug binary → `bin/<os>-<arch>-debug-<libc>-dynamic/`, codesigned, symlinked to `bin/<project>`.
- `rake dist` — release binary for the host (macOS: signed; needs a Developer ID, see `mem:pitfalls`).
- `rake spec` — full Spectator unit suite.
- `rake lint` (`rake "lint[no_color]"`) — Ameba.
- `rake cover` — kcov coverage → `coverage/`.
- `rake run` — `shards run` the debug binary.
- `rake release[yes]` — branch-then-tag release (see `mem:build`); pushes nothing.
- `rake "update_formula[VERSION,ASSETS_DIR]"` — rewrite the Homebrew formula (CI passes `artifacts`).
- `rake -T` — list tasks.

RuboCop for the Ruby build files: `bundle exec rubocop rakelib Rakefile`.

Darwin note: standard BSD userland; commands otherwise behave as on Linux. (The Claude Code sandbox restricts `ps`/`kill` and non-allowlisted network hosts, but that is not a property of the machine.)
