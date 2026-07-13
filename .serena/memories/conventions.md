# Conventions

Follow the user's `my:` skills: `general`, `development`, `development-crystal` (and `development-ruby` for rakelib).

## Crystal
- Named parameters; force keyword args with a splat (`def f(x, *, y:)`). `record` for value types; `def_equals`/`def_clone` on models. Nilable `x : T?` → add `x! : T` bang getter that raises.
- `&.method` over `{ |x| x.method }`; do/end for multi-line blocks, `{}` for single-line.
- Prefer instance methods over class/static methods (`mem:` note: objects + instance methods).
- Version is single-sourced in `shard.yml`; `version.cr` reads it at compile time — never hardcode elsewhere.

## Ruby (rakelib)
- Keyword arguments throughout factories/helpers. Values via `Data.define`; constants at module level (not inside `Data.define do` blocks — `Lint/ConstantDefinitionInBlock`). `%r{}` regex literals, double-quoted strings (per `.rubocop.yml`).

## Editing tooling
- **Serena `replace_symbol_body`/symbol edits corrupt Crystal (`.cr`) files** — navigate with Serena, but make edits with Edit/Write. Ruby files are safe to edit either way, but Edit/Write is the norm here.
- Serena project languages: `crystal`, `ruby` (`.serena/project.yml`); a language change needs a Serena MCP restart to take effect.

## Spelling
- `cspell.dict` holds project words; add new domain terms there to keep spell-check clean.
