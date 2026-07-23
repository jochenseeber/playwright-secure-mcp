# Changelog

## [1.1.0](https://github.com/jochenseeber/playwright-secure-mcp/compare/v1.0.0...v1.1.0) (2026-07-23)

### ⚠ BREAKING CHANGES

* cache items and scope secrets to URL ([eb57627](https://github.com/jochenseeber/playwright-secure-mcp/commit/eb57627))

### Features

* type one-time passwords fetched live from 1Password ([d3b55f0](https://github.com/jochenseeber/playwright-secure-mcp/commit/d3b55f0))
* add a --version option that prints the version ([b971f3c](https://github.com/jochenseeber/playwright-secure-mcp/commit/b971f3c))
* cache items and scope secrets to URL ([eb57627](https://github.com/jochenseeber/playwright-secure-mcp/commit/eb57627))

### Bug Fixes

* read the service-account token from the full item object ([1ffa4a0](https://github.com/jochenseeber/playwright-secure-mcp/commit/1ffa4a0))
* redact upstream stderr and exception logs ([5f1f10a](https://github.com/jochenseeber/playwright-secure-mcp/commit/5f1f10a))
* gate discovery ranking on path match for typing consistency ([e2c9f53](https://github.com/jochenseeber/playwright-secure-mcp/commit/e2c9f53))
* authorize secret typing only on exact host and matching port ([68644e7](https://github.com/jochenseeber/playwright-secure-mcp/commit/68644e7))
* cache and redact only credential field values ([3b462e8](https://github.com/jochenseeber/playwright-secure-mcp/commit/3b462e8))
* redact secrets within JSON string leaves, not the serialized line ([ce4a66d](https://github.com/jochenseeber/playwright-secure-mcp/commit/ce4a66d))
* parse concatenated JSON objects from batched op item get ([4fe8ea4](https://github.com/jochenseeber/playwright-secure-mcp/commit/4fe8ea4))

## 1.0.0 (2026-07-16)

### Features

* Initial commit ([b355b6e](https://github.com/jochenseeber/playwright-secure-mcp/commit/b355b6e))
