# Configuration

`mcp-check` scans Model Context Protocol configuration files and `SKILL.md` bundles without executing them. Use this page to see which MCP config shapes and preset locations are supported.

Current MCP config support:

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

## Project Discovery

Scan known repository-local config files in one command:

```bash
mcp-check scan --project . --fail-on high
mcp-check scan --project ./my-repo --format sarif --output results.sarif
```

Discovery checks these paths, in order:

- `.mcp.json` ([Claude Code project scope](https://code.claude.com/docs/en/mcp#project-scope))
- `.cursor/mcp.json` ([Cursor project configuration](https://cursor.com/docs/mcp))
- `.vscode/mcp.json` ([VS Code workspace configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration))

Only the specified directory is inspected; discovery does not search parent
directories, user profiles, or nested projects. Existing symlinked files are
read as with explicit file scans. JSON parsing remains strict: comments and
trailing commas are not supported. Missing optional files are skipped, but no
matching files, malformed configs, or non-file config paths exit with code 2.
All discovered configs are scanned independently, without client precedence
rules or server-name deduplication. Reports list the scanned source paths.

`--project`, `--preset`, and an explicit config path are mutually exclusive.
Output formats, suppressions, and failure thresholds work as with file scans.
`--baseline` compares against the combined project report once. Baseline and
suppression matching use the existing server/rule fields, not file identity.

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
