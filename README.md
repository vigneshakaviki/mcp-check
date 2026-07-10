# mcp-check

Offline security checks for Model Context Protocol server configurations.

Before an AI coding agent can access a terminal, filesystem, repository, network, or secrets, `mcp-check` shows what the configured MCP server is being allowed to run and where it may reach. It is static analysis: it never launches or connects to an MCP server.

## Install

```bash
python -m pip install .
```

## Scan

```bash
mcp-check scan ./claude_desktop_config.json
mcp-check scan ./claude_desktop_config.json --format json
mcp-check scan ./claude_desktop_config.json --format sarif --output results.sarif
mcp-check scan ./claude_desktop_config.json --fail-on high
```

The first release supports JSON files with an `mcpServers` object, including the common Claude and Cursor-style shape. The scanner is offline and does not execute commands from the configuration.

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
      - uses: your-org/mcp-check@v0.1.0
        with:
          paths: |
            config/claude_desktop_config.json
          fail-on: high
```

## Rules

| ID | Checks |
| --- | --- |
| MCP001 | privileged, destructive, shell, download, or dynamic execution commands |
| MCP002 | sensitive local paths such as SSH keys, cloud credentials, and `.env` files |
| MCP003 | credentials embedded directly in configuration |
| MCP004 | unpinned package execution through `npx`, `uvx`, `pip`, and related tools |
| MCP005 | insecure remote HTTP URLs |
| MCP006 | remote network destinations in command arguments or environment values |
| MCP007 | prompt-injection language in tool descriptions, prompts, annotations, or metadata |
| MCP008 | privileged containers, host namespaces, Docker socket mounts, broad host mounts, or broad environment inheritance |

Findings include severity, confidence, evidence, location, and a remediation. Credential evidence is redacted in all reports.

These rules cover static signals from published MCP security research: tool poisoning, mutable supply-chain references, overbroad local privileges, static credentials, and weak transport. Runtime controls such as semantic approval, per-tool authorization, provenance signing, and audit logging still need to be enforced by the MCP client, gateway, or server runtime.

## Development

```bash
python -m pip install pytest
pytest
python -m mcp_check scan tests/fixtures/mixed.json
```

## Security

This project performs static analysis only. Please report vulnerabilities through the process in `SECURITY.md`.
