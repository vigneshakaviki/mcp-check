# Configuration

`mcp-check` scans JSON, YAML, and TOML files with an `mcpServers` object.

```bash
mcp-check scan ./claude_desktop_config.json
mcp-check scan ./mcp.yaml
mcp-check scan ./mcp.toml
```

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
