# Changelog

All notable changes to `mcp-check` are documented here.

## v0.5.0

- Added `mcp-check rules` and `mcp-check rules --format json`.
- Added `mcp-check --version`.
- Added dedicated docs for rules, configuration, and GitHub Action usage.
- Added Marketplace-ready Action branding.
- Added changelog, support guide, code of conduct, pull request template, issue template config, and Dependabot config.
- Preserved capability summaries when scanning multiple preset paths.
- Centralized report version output on the package version.

## v0.4.0

- Added `MCP011` for local HTTP transport hardening and wildcard network binds.
- Reclassified local HTTP MCP URLs as transport findings instead of SSRF.
- Added OAuth token-in-query detection.
- Added PKCE S256 metadata detection.
- Filtered placeholder URLs from capability summaries.
- Added regression examples for local HTTP transport, wildcard binds, and OAuth token query strings.

## v0.3.0

- Added `MCP009` for SSRF-prone URLs, private networks, cloud metadata endpoints, and dangerous URL schemes.
- Added `MCP010` for OAuth credentials, broad scopes, unsafe OAuth endpoint URLs, and token risks.
- Added capability summaries to terminal and JSON output.

## v0.2.0

- Added JSON, YAML, and TOML config parsing.
- Added explicit suppression files with suppressed findings visible in JSON and SARIF.
- Added common client path presets for Claude Desktop, Claude Code, and Cursor.
- Added packaging metadata, PyPI publish workflow, and Homebrew guidance.

## v0.1.0

- Initial public release.
- Added static rules for commands, paths, secrets, package provenance, network access, metadata injection, and runtime privileges.
- Added terminal, JSON, and SARIF output.
- Added GitHub Action support.
