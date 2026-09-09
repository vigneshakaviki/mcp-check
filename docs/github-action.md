# GitHub Action

Use `mcp-check` as a GitHub Action to scan MCP config changes in pull requests and upload SARIF to GitHub code scanning.

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

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `paths` | yes | | Newline-separated JSON/YAML/TOML MCP config paths |
| `fail-on` | no | `high` | Minimum severity that fails the Action |
| `suppressions` | no | | Optional suppression file path |
| `upload-sarif` | no | `true` | Upload results to GitHub code scanning; set to `false` for a standalone CI check |

The Action installs the scanner from its own directory. Your repository does not
need a `pyproject.toml` or `setup.py`. Config and suppression paths remain relative
to your checked-out repository.

## Use without GitHub code scanning

To use the scan as a CI check without uploading to GitHub code scanning, disable
the upload. The scan still generates SARIF and fails on the configured severity.
This mode only needs read access to your repository:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: vigneshakaviki/mcp-check@main
    id: mcp
    with:
      paths: .vscode/mcp.json
      fail-on: high
      upload-sarif: "false"
```

The installation fix and `upload-sarif` input are unreleased and require a commit
containing these changes; `v0.6.0` does not include them. Once released, replace
`main` with that release's full commit SHA for reproducible runs.

The `sarif` output contains the generated report path
(`steps.mcp.outputs.sarif`). Uploading is enabled by default and requires GitHub
code scanning access and `security-events: write` permission.
