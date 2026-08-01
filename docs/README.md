# MCP Security Docs

`mcp-check` is an offline MCP security scanner for Model Context Protocol configs and `SKILL.md` bundles.

Use these docs for the main user flows:

- [MCP security rules](rules.md): rule catalog, severity, and rationale
- [MCP config support](configuration.md): supported config shapes, presets, and output formats
- [GitHub Action for MCP security scanning](github-action.md): CI usage and SARIF upload
- [MCP Security Starts Before Server Startup](blog/scan-mcp-configs-before-they-run.md): why static MCP scanning belongs before approval and execution

Core workflows:

- scan MCP configs before install
- scan `SKILL.md` bundles before use
- add MCP security checks to pull requests
