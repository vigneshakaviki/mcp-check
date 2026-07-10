# Rule Reference

`mcp-check` rules are stable identifiers. Use these IDs in suppressions, CI policy, and SARIF review.

| ID | Default severity | Rule | What it detects |
| --- | --- | --- | --- |
| MCP001 | high-critical | Dangerous command execution | Privileged, destructive, shell, download, or dynamic execution commands |
| MCP002 | high | Sensitive local path | SSH keys, cloud credentials, environment files, home directories, and other sensitive paths |
| MCP003 | critical | Embedded credential | Credentials or credential-like values embedded directly in MCP configuration |
| MCP004 | medium-high | Mutable package or image | Unpinned packages, mutable Git refs, and mutable container images |
| MCP005 | high | Insecure remote HTTP URL | Remote MCP URLs that use HTTP instead of HTTPS |
| MCP006 | medium | Remote network access | Remote destinations in command arguments or environment values |
| MCP007 | high | Prompt-injection metadata | Suspicious prompt-injection language in tool descriptions, prompts, annotations, or metadata |
| MCP008 | high-critical | Dangerous runtime privileges | Privileged containers, host namespaces, Docker socket mounts, broad mounts, or broad environment inheritance |
| MCP009 | high-critical | SSRF-prone URL | Private network targets, cloud metadata endpoints, reserved addresses, or dangerous URL schemes |
| MCP010 | high-critical | OAuth or token risk | OAuth/bearer credentials, broad scopes, unsafe OAuth URLs, token query strings, or weak PKCE metadata |
| MCP011 | medium-high | Transport hardening gap | Local HTTP transport hardening gaps and wildcard network binds |

List rules from the CLI:

```bash
mcp-check rules
mcp-check rules --format json
```

## Suppressions

Suppressions are intentionally explicit. Prefer suppressing one finding at a time.

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

Suppressed findings remain visible in JSON and SARIF output with the suppression reason.
