# GitHub Action

Use `mcp-check` in pull requests to scan MCP config changes and upload SARIF to GitHub code scanning.

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

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `paths` | yes | | Newline-separated JSON/YAML/TOML MCP config paths |
| `fail-on` | no | `high` | Minimum severity that fails the Action |
| `suppressions` | no | | Optional suppression file path |
