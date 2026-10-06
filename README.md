# mcp-check

[![Test](https://github.com/vigneshakaviki/mcp-check/actions/workflows/test.yml/badge.svg)](https://github.com/vigneshakaviki/mcp-check/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/vigneshakaviki/mcp-check)](https://github.com/vigneshakaviki/mcp-check/releases)
[![PyPI](https://img.shields.io/pypi/v/mcp-check-security)](https://pypi.org/project/mcp-check-security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Review MCP configs and agent skills before they run. Offline, deterministic, and built for pull requests.

`mcp-check` is a static security scanner for Model Context Protocol setup files and `SKILL.md` bundles. Scan locally, review actionable findings, and gate pull requests with JSON or SARIF reports. No account, API key, or model required.

It detects risky shell access, embedded secrets, prompt injection language, unpinned installs, Docker privilege, private-network URLs, weak transport settings, and approval bypasses.

It never launches, connects to, or executes an MCP server or skill bundle.

## Who This Is For

- Developers adding third-party MCP servers to Claude, Cursor, Copilot CLI, Codex, or VS Code
- Security reviewers checking MCP changes in pull requests
- Teams auditing `SKILL.md` bundles before enabling them for agents
- Maintainers who want a GitHub Action for MCP security scanning

## Why Offline Matters

`mcp-check` reviews static config and skill files before anything executes. Once installed, scanning needs no network access and does not send content to an analysis service. Other scanners also offer local analysis; this project's focus is a small, predictable pre-execution check.

That makes it useful for:

- pre-install review
- CI and pull request gates
- auditing example configs from public repos
- checking skills without running bundled scripts

## Quick Start

### Scan MCP Configs Before Install

```bash
python -m pip install mcp-check-security
mcp-check scan ./claude_desktop_config.json
```

### Audit `SKILL.md` Bundles Before Use

```bash
mcp-check scan-skill ./skills/my-skill
```

The development version can scan a whole skill library in one command:

```bash
# From a checkout until the next release:
python -m pip install .
mcp-check scan-skill ./skills --recursive --fail-on high
```

See [skill library scanning](docs/skills.md) for CI, baselines, and discovery boundaries.

### Add MCP Security Checks To Pull Requests

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
      - uses: vigneshakaviki/mcp-check@v0.6.0
        with:
          paths: |
            ./.vscode/mcp.json
            ./.codex/config.toml
```

## Documentation

- [MCP security docs index](docs/README.md)
- [MCP security rules](docs/rules.md)
- [MCP config support](docs/configuration.md)
- [GitHub Action for MCP security scanning](docs/github-action.md)
- [Skill library scanning](docs/skills.md)
- [Market research and priorities](competitor-profiles/_summary.md)
- [Packaging](PACKAGING.md)
- [Changelog](CHANGELOG.md)
- [Support](SUPPORT.md)

## Why

MCP configs can give AI coding agents access to terminals, repositories, filesystems, networks, Docker, and credentials. That is useful, but it also creates a review problem: a small JSON config can quietly grant a lot of power.

`mcp-check` makes those risks visible before execution.

## Example Output

### MCP Config Scan

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

### Skill Bundle Scan

```bash
mcp-check scan-skill tests/fixtures/skill-unsafe
```

```text
[CRITICAL] Credential appears directly in skill content
  MCP003 SKILL.md

[CRITICAL] Skill content contains a download and execute pipeline
  MCP001 scripts/bootstrap.sh

[HIGH] Skill content disables TLS certificate verification
  MCP012 scripts/bootstrap.sh
```

## Install

From a checkout:

```bash
python -m pip install .
```

For development:

```bash
uv run mcp-check scan examples/unsafe/docker-socket.json
```

## Supported Clients

| Client | Shape | Example path |
| --- | --- | --- |
| Claude Desktop | `mcpServers` | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | `mcpServers` | `~/.claude.json` |
| Cursor | `mcpServers` | `~/.cursor/mcp.json` |
| GitHub Copilot CLI | `mcpServers` | `~/.copilot/mcp-config.json` |
| Codex | `mcp_servers` | `~/.codex/config.toml` |
| VS Code | `servers` | `./.vscode/mcp.json` |

## Scan Commands

```bash
mcp-check --version
mcp-check rules
mcp-check scan ./claude_desktop_config.json
mcp-check scan-skill ./my-skill
mcp-check scan ./mcp.yaml
mcp-check scan ./mcp.toml
mcp-check scan ~/.codex/config.toml
mcp-check scan ./.vscode/mcp.json
mcp-check scan ./claude_desktop_config.json --format json
mcp-check scan ./claude_desktop_config.json --format sarif --output results.sarif
mcp-check scan ./claude_desktop_config.json --fail-on high
mcp-check scan ./claude_desktop_config.json --suppressions ./examples/suppressions.json
mcp-check scan ./claude_desktop_config.json --baseline ./previous-results.json
mcp-check scan-skill ./my-skill --format json
```

The scanner supports JSON, YAML, and TOML. It recognizes `mcpServers` (Claude, Cursor, Gemini, and Copilot CLI), `servers` (VS Code), and `mcp_servers` (Codex), plus the common `url`, `uri`, `httpUrl`, and `serverUrl` remote URL fields.

## Supported Risks

| Risk | What `mcp-check` flags |
| --- | --- |
| Embedded credentials | API keys, bearer tokens, URL credentials, client secrets |
| Dangerous shell access | `sudo`, `rm -rf`, download-and-execute, dynamic execution |
| Prompt injection | hidden or coercive instructions in MCP metadata and skills |
| Mutable installs | unpinned `npx`, `uvx`, Git refs, mutable container images |
| Runtime privilege | Docker socket, broad mounts, privileged container flags, `LD_PRELOAD`/`NODE_OPTIONS`-style code-injection environment variables |
| Network and SSRF | insecure HTTP, cloud metadata endpoints, private network URLs, decimal/hex/octal IP obfuscation |
| Transport weakness | TLS verification disable, wildcard bind, wildcard origin |
| Approval bypass | `alwaysAllow`, `autoApprove`, and whole-server `trust` style settings |

## Client Presets

List common MCP client config paths:

```bash
mcp-check paths
mcp-check paths --preset claude-desktop
mcp-check paths --preset copilot-cli
mcp-check paths --preset codex
mcp-check paths --preset cursor --existing
```

Scan existing configs from known client locations:

```bash
mcp-check scan --preset all
mcp-check scan --preset claude-desktop
mcp-check scan --preset copilot-cli
mcp-check scan --preset codex
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
| `examples/unsafe/header-secret.json` | literal bearer credential in remote MCP headers |
| `examples/unsafe/tls-verification-disabled.json` | TLS certificate verification disabled by flag and environment |
| `examples/unsafe/wildcard-origin.json` | wildcard browser origin policy |
| `examples/unsafe/hidden-unicode-description.json` | invisible Unicode control in tool metadata |
| `examples/unsafe/auto-approved-tools.json` | MCP tools configured to bypass per-call approval |
| `examples/unsafe/trust-all-server.json` | server-level `trust` flag that bypasses approval for every tool |
| `examples/unsafe/env-var-injection.json` | `LD_PRELOAD` and `NODE_OPTIONS` set on the spawned MCP server process |
| `examples/unsafe/obfuscated-ssrf-ip.json` | cloud metadata address written as an obfuscated decimal IP |

## Skill Bundles

Scan a skill directory or explicit `SKILL.md` file without executing bundled scripts:

```bash
mcp-check scan-skill ./skills/my-skill
mcp-check scan-skill ./skills/my-skill/SKILL.md
```

Skill scanning reviews:

- `SKILL.md` instructions
- text files under `references/`
- text scripts under `scripts/`
- text assets under `assets/`

It detects embedded secrets, prompt-injection language, dangerous shell/download snippets, mutable package installs, sensitive paths, unsafe URLs, and disabled TLS verification instructions.

## Why Teams Use It

- Review third-party MCP server configs before enabling them
- Catch risky MCP changes in pull requests with SARIF output
- Audit public example configs without running them
- Check `SKILL.md` bundles from agent ecosystems before sharing them internally

## Comparison

Choose `mcp-check` for a deterministic check of local MCP configs and skill bundles before enabling them. It produces review evidence and severity-based CI gates without starting servers, contacting endpoints, or running a model.

For broader discovery and hosted analysis, evaluate [Snyk Agent Scan](https://github.com/snyk/agent-scan). For live MCP inspection or deeper skill analysis, evaluate [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) and [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner). Cisco also provides local/static analysis options; offline scanning is not exclusive to this project.

Static findings are signals to review, not proof that a bundle is safe. `mcp-check` does not provide runtime enforcement, malware sandboxing, semantic prompt-injection analysis, or a measured detection-rate guarantee. See the [dated research and implementation priorities](competitor-profiles/_summary.md).

## Security Research Coverage

The rule set is shaped by published MCP security guidance and common failure modes:

- token and secret exposure
- prompt injection in descriptions and skills
- overbroad local or Docker privilege
- mutable package and image references
- unsafe transport and private-network access

See [MCP security rules](docs/rules.md) for rule-by-rule details and references.

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
      - uses: vigneshakaviki/mcp-check@v0.6.0
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
| MCP005-MCP011 | network, metadata, runtime, SSRF, OAuth, and transport risks (including code-injection environment variables and obfuscated-IP SSRF bypasses) |
| MCP012 | TLS certificate verification or secure transport explicitly disabled |
| MCP013 | named/wildcard MCP tools, or a whole server via a `trust` flag, configured for automatic approval |

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

Baseline mode compares a fresh scan against a previous `mcp-check --format json` or `--format sarif` report and only shows new findings. That makes it practical to adopt the scanner in a repo that already has accepted risk.

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

- More MCP client config path presets and project-level discovery.
- Homebrew packaging and signed release artifacts.
- Optional provenance checks for known MCP server packages.

## Security

This project performs static analysis only. Please report vulnerabilities through the process in `SECURITY.md`.
