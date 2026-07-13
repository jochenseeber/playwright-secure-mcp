# Build & Release (rakelib)

Root `Rakefile` is thin: `require_relative "rakelib/crystal"; Crystal::Project.create.define_tasks`.

## rakelib layout (all `.rb` — libraries, not `.rake`; not auto-imported)
- `support.rb` — generic, language-agnostic: `Platform` (`Data.define(:os, :arch)`, `.detect`), `Version` (`Data.define(:major,:minor,:patch,:prerelease)`, `.parse`, `<=>`, `to_s`), `capture`.
- `codesign.rb` — generic macOS signing helpers: `codesign_binary(path:, release:)`, identity via `CODESIGN_IDENTITY` env or 1Password item tagged `codesign/<git-email>/<release|debug>`.
- `release.rb` — generic `define_release_task(name:, read_version:, write_version:, version_files:, mainline:, tag_prefix:, branch_suffix:)` + helpers (`git_capture`, `latest_release_ref`, `detect_bump`). Version I/O injected as lambdas → not tied to shard.yml.
- `formula.rb` — generic `define_formula_task(name:, formula_path:, binary_prefix:, default_assets_dir:)` + `write_formula`.
- `crystal.rb` — the only file that creates tasks. `module Crystal` with `SHARD_PATH`, `Component`, `Profile` (`<os>-<arch>-<mode>-<libc>-<link>` dir), `Project` (`include Rake::DSL`). `Project.create` builds from shard.yml + `Platform.detect`; `#define_tasks` defines aggregates + per-component namespaces and calls the generic factories.

## libc/link detection (in Crystal::Project, host-aware)
`os_kind` → `:macosx`/`:alpine`/`:debian` (Alpine via `/etc/alpine-release` or `/etc/os-release` ID). `libc`: system/musl/glibc. Release link: static only for musl (Alpine), else dynamic; debug always dynamic. `os` stays `darwin`/`linux` so bin-dir + release-artifact + formula names are stable.

## Release flow (branch-then-tag)
`main` carries `X.Y.0-dev`. `rake release` from main: creates branch `vX.Y.x`, tags `vX.Y.0` there, sets branch to `X.Y.1-dev`, bumps main to `X.(Y+1).0-dev`. Patch releases cut the same way from the release branch. Pushing a `vX.Y.Z` tag triggers `.github/workflows/release.yml`: builds linux static-musl (Alpine container) + macOS signed+notarized, publishes GitHub release, then `rake update_formula` rewrites the root Homebrew formula and commits to main.

To reuse rakelib in another project: copy `Rakefile` + `rakelib/`; config derives from `shard.yml`.
