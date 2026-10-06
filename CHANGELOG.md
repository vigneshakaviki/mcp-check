# Changelog

All notable changes to `mcp-check` are documented here.

## Unreleased

- Added `scan-skill DIR --recursive` to scan local skill libraries with one report, severity gate, and baseline comparison.
- Added per-finding source paths to JSON and terminal reports. SARIF now points to actual skill files and preserves individual config paths in merged reports.
- Made new baselines file-aware so identical findings in different bundles are not silently treated as previously accepted. Single-bundle scans still accept legacy reports; recursive scans require source-aware baselines.
- Reject symlinked skill entry files and content inside bundles instead of reading linked targets. Recursive discovery skips symlinked directories and common dependency/cache directories.
- Added dated market research and narrowed positioning to deterministic pre-execution review, with explicit analysis limits.
- Added `scan-skill` for offline scanning of skill bundles rooted at `SKILL.md`, including sibling `scripts/`, `references/`, and text assets.
- `MCP008` now detects code-injection environment variables (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `PYTHONPATH`, and similar) set on an MCP server or exported in skill scripts.
- `MCP009` now decodes decimal, hexadecimal, and octal IP obfuscation (for example `2130706433` for `127.0.0.1`) before evaluating SSRF and cloud-metadata targets, closing a filter-bypass gap shared with skill URL scanning.
- `MCP013` now detects the Gemini CLI-style server-level `trust: true` flag, which bypasses per-call approval for every tool on that server.
- Added `examples/unsafe/env-var-injection.json`, `examples/unsafe/trust-all-server.json`, and `examples/unsafe/obfuscated-ssrf-ip.json`.

## v0.6.0 - 2026-07-27

- Added preset path discovery for Codex `~/.codex/config.toml` and GitHub Copilot CLI `~/.copilot/mcp-config.json`.
- Added `MCP012` for explicitly disabled TLS certificate verification.
- Added `MCP013` for named and wildcard MCP tool auto-approval settings.
- Expanded embedded-credential detection to remote headers, URL user information, nested auth fields, and command arguments while preserving environment/input references.
- Added wildcard-origin and hidden-Unicode metadata checks, plus broader OAuth scope detection.
- Added support for VS Code `servers`, Codex `mcp_servers`, and remote URL field aliases used by Gemini and Windsurf.
- Added `--baseline` support for diffing against a previous JSON or SARIF report.
- Terminal reports now call out new, unchanged, and absent findings when a baseline is supplied.
- SARIF output now carries baseline comparison metadata for diff mode.

## v0.5.0 - 2026-07-10

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
