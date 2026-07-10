# Contributing

`mcp-check` is a small static scanner. Good contributions are narrow, testable, and tied to a concrete MCP config risk.

## Setup

```bash
uv run --with 'pytest>=8' pytest -q
uv run mcp-check scan examples/unsafe/docker-socket.json
```

## Good First Contributions

- Add a new unsafe example config under `examples/unsafe/`.
- Add a scanner rule for a statically detectable MCP risk.
- Reduce a false positive found in a real public config.
- Add support for another MCP client config shape.
- Improve SARIF output for GitHub code scanning.

## Rule Guidelines

Each rule should include:

- A clear rule ID and title.
- Severity and confidence.
- Evidence that helps the user find the risky config field.
- A remediation that tells the user what to change.
- Tests that cover both unsafe and safe examples.

Avoid rules that require running untrusted MCP code. The scanner should stay offline by default.
