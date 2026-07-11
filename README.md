# mcp-check

[![Test](https://github.com/vigneshakaviki/mcp-check/actions/workflows/test.yml/badge.svg)](https://github.com/vigneshakaviki/mcp-check/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/vigneshakaviki/mcp-check)](https://github.com/vigneshakaviki/mcp-check/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Security linting for Model Context Protocol server configs before your AI agent runs them.

`mcp-check` is an offline static scanner for MCP configuration files. It shows when a config grants risky access to shell commands, local files, Docker, network destinations, package installers, or secrets.

It never launches or connects to an MCP server.

## Documentation

- [Rule reference](docs/rules.md)
- [Configuration](docs/configuration.md)
- [GitHub Action](docs/github-action.md)
- [Packaging](PACKAGING.md)
- [Changelog](CHANGELOG.md)
- [Support](SUPPORT.md)

## Why

MCP configs can give AI coding agents access to terminals, repositories, filesystems, networks, Docker, and credentials. That is useful, but it also creates a review problem: a small JSON config can quietly grant a lot of power.

`mcp-check` makes those risks visible before execution.

## Quick Demo

```bash
mcp-check scan examples/unsafe/docker-socket.json
```

Example output:

```text
[HIGH] MCP container image is not immutable
  MCP004 args
  Evidence: docker example/mcp:latest

[CRITICAL] MCP server mounts the Docker socket
  MCP008 args.docker_socket
  Evidence: /var/run/docker.sock

[CRITICAL] MCP server requests privileged container execution
  MCP008 args.privileged
```

## Install

From PyPI:

```bash
python -m pip install mcp-check-security
```

From a checkout:

```bash
python -m pip install .
```

For development:

```bash
uv run mcp-check scan examples/unsafe/docker-socket.json
```

## Scan

```bash
mcp-check --version
mcp-check rules
mcp-check scan ./claude_desktop_config.json
mcp-check scan ./mcp.yaml
mcp-check scan ./mcp.toml
mcp-check scan ./claude_desktop_config.json --format json
mcp-check scan ./claude_desktop_config.json --format sarif --output results.sarif
mcp-check scan ./claude_desktop_config.json --fail-on high
mcp-check scan ./claude_desktop_config.json --suppressions ./examples/suppressions.json
```

The scanner supports JSON, YAML, and TOML files with an `mcpServers` object, including common Claude Desktop and Cursor-style shapes.

## Client Presets

List common MCP client config paths:

```bash
mcp-check paths
mcp-check paths --preset claude-desktop
mcp-check paths --preset cursor --existing
```

Scan existing configs from known client locations:

```bash
mcp-check scan --preset all
mcp-check scan --preset claude-desktop
mcp-check scan --preset cursor
```

## Example Configs

Use the example configs to see what each rule catches:

```bash
for file in examples/unsafe/*.json; do
  mcp-check scan "$file"
done
```

Examples included:

| File | Risk shown |
| --- | --- |
| `examples/unsafe/leaked-secret.json` | plaintext API key |
| `examples/unsafe/docker-socket.json` | privileged Docker and Docker socket |
| `examples/unsafe/prompt-injection-description.json` | suspicious tool metadata |
| `examples/unsafe/unpinned-npx.json` | mutable package install |
| `examples/unsafe/http-remote-server.json` | insecure remote MCP URL |
| `examples/unsafe/ssh-path-mount.json` | sensitive local path |
| `examples/unsafe/git-main-install.json` | mutable Git branch install |
| `examples/unsafe/shell-command.json` | shell and download execution |
| `examples/unsafe/private-network-url.json` | SSRF, cloud metadata, and dangerous URL schemes |
| `examples/unsafe/oauth-broad-scope.json` | broad OAuth scopes, HTTP OAuth URLs, and embedded client secret |
| `examples/unsafe/local-http-transport.json` | local HTTP MCP transport requiring auth/origin hardening |
| `examples/unsafe/wildcard-bind.json` | MCP server binding to all interfaces |
| `examples/unsafe/oauth-token-query.json` | OAuth token in URL query and missing PKCE S256 metadata |

## GitHub Action

```yaml
name: MCP security

on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: vigneshakaviki/mcp-check@v0.5.0
        with:
          paths: |
            config/claude_desktop_config.json
          suppressions: config/mcp-check-suppressions.json
          fail-on: high
```

## Suppressions

Known findings can be suppressed explicitly by rule, server, and location. Suppressed findings are still visible in JSON and SARIF output.

```json
{
  "suppressions": [
    {
      "rule_id": "MCP004",
      "server": "npx-demo",
      "location": "args",
      "reason": "Reviewed package source; pinning tracked separately."
    }
  ]
}
```

Use `*` for `server` or `location` only when the suppression really applies broadly.

## Rules

| ID | Checks |
| --- | --- |
| MCP001 | privileged, destructive, shell, download, or dynamic execution commands |
| MCP002 | sensitive local paths such as SSH keys, cloud credentials, and `.env` files |
| MCP003 | credentials embedded directly in configuration |
| MCP004 | unpinned packages, mutable Git refs, and mutable container images |
| MCP005-MCP011 | network, metadata, runtime, SSRF, OAuth, and transport risks |

Findings include severity, confidence, evidence, location, and a remediation. Credential evidence is redacted in all reports.

See [docs/rules.md](docs/rules.md) or run `mcp-check rules` for the full rule catalog.

Terminal and JSON reports also include a capability summary for quick review:

```text
Capabilities:
  shell: yes
  docker: yes
  network: https://example.test/install.sh
  packages: docker run --rm
```

These rules cover static signals from published MCP security research: tool poisoning, mutable supply-chain references, overbroad local privileges, static credentials, and weak transport. Runtime controls such as semantic approval, per-tool authorization, provenance signing, sandboxing, and audit logging still need to be enforced by the MCP client, gateway, or server runtime.

## When To Use It

- Before adding a new MCP server to Claude Desktop, Cursor, or an AI coding agent.
- In pull requests that add or change MCP configs.
- When reviewing an MCP server repo's example config.
- Before sharing internal MCP setup snippets with a team.

## Development

```bash
uv run --with 'pytest>=8' pytest -q
uv run mcp-check scan tests/fixtures/mixed.json
```

## Roadmap

- Baseline mode for existing findings.
- More MCP client config path presets.
- Publish to PyPI and Homebrew.
- Optional provenance checks for known MCP server packages.

## Security

This project performs static analysis only. Please report vulnerabilities through the process in `SECURITY.md`.
