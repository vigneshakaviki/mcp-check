# Configuration

`mcp-check` scans JSON, YAML, and TOML files using these current client shapes:

- `mcpServers`: Claude, Cursor, Gemini CLI, and GitHub Copilot CLI
- `servers`: VS Code `mcp.json`
- `mcp_servers`: Codex `config.toml`

Remote URLs can use `url`, `uri`, `httpUrl`, or `serverUrl`.

```bash
mcp-check scan ./claude_desktop_config.json
mcp-check scan ./mcp.yaml
mcp-check scan ./mcp.toml
mcp-check scan ~/.codex/config.toml
mcp-check scan ./.vscode/mcp.json
```

Secrets referenced through client-supported environment or password-input syntax are treated as references rather than embedded credentials. Literal secrets in `env`, headers, URLs, or command arguments are reported and redacted.

Client-specific server settings are also reviewed when present. Empty `alwaysAllow` and `autoApprove` lists are accepted; named pre-approvals are reported at medium severity and wildcard approval at high severity.

## Client Presets

List common MCP config paths:

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

## Output Formats

```bash
mcp-check scan ./mcp.json --format terminal
mcp-check scan ./mcp.json --format json
mcp-check scan ./mcp.json --format sarif --output results.sarif
mcp-check scan ./mcp.json --baseline ./baseline.json
```

## CI Failure Threshold

```bash
mcp-check scan ./mcp.json --fail-on high
```

Allowed thresholds are `low`, `medium`, `high`, and `critical`.
