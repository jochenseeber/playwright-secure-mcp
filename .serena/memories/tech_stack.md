# Tech Stack

- **Crystal** `>= 1.20` (`shard.yml`); CI pins 1.20.3. Deps via **shards** (`shard.yml`/`shard.lock`, installed to `lib/`).
- **Build**: Rake (Ruby 4.0.x) — tasks live in `rakelib/*.rb` (see `mem:build`), not the Rakefile.
- **Tests**: Spectator (unit specs in `spec/*_spec.cr`). `spec_helper.cr`. Coverage via **kcov**. (A per-component rspec `test` task exists but there is no `test/` dir yet.)
- **Lint**: Ameba (Crystal, `lib/ameba/bin/ameba`); RuboCop for the Ruby rakelib/Rakefile (Gemfile: rubocop, ruby-lsp, ruby-lsp-rspec; config `.rubocop.yml`).
- **Upstream runtime dep**: `@playwright/mcp` fetched via pnpm (default)/npx, or a preinstalled binary.
- **1Password CLI** `op` (2.x) for secret resolution; desktop-app integration for auth.
- **Platform FFI**: macOS Security framework (Secure Enclave) in `secure_enclave_cipher.cr`; Linux `tss2-esys` (TPM 2.0) in `tpm_cipher.cr`. Release links: `-ltss2-esys -ltss2-sys -ltss2-mu -ltss2-rc -ltss2-tcti-device` (Alpine static).
- **Distribution**: signed+notarized macOS binary, static-musl Linux binary; GitHub Releases; Homebrew formula at repo root (`playwright-secure-mcp.rb`).
