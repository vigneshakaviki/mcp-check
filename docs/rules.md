# Rule Reference

`mcp-check` rules are stable identifiers. Use these IDs in suppressions, CI policy, and SARIF review.

| ID | Default severity | Rule | What it detects |
| --- | --- | --- | --- |
| MCP001 | high-critical | Dangerous command execution | Privileged, destructive, shell, download, or dynamic execution commands |
| MCP002 | high | Sensitive local path | SSH keys, cloud credentials, environment files, home directories, and other sensitive paths |
| MCP003 | critical | Embedded credential | Credentials embedded in environment values, headers, URLs, nested auth fields, or command arguments |
| MCP004 | medium-high | Mutable package or image | Unpinned packages, mutable Git refs, and mutable container images |
| MCP005 | high | Insecure remote HTTP URL | Remote MCP URLs that use HTTP instead of HTTPS |
| MCP006 | medium | Remote network access | Remote destinations in command arguments or environment values |
| MCP007 | high | Prompt-injection metadata | Suspicious prompt-injection language or hidden Unicode controls in tool descriptions, prompts, annotations, or metadata |
| MCP008 | high-critical | Dangerous runtime privileges | Privileged containers, host namespaces, Docker socket mounts, broad mounts, or broad environment inheritance |
| MCP009 | high-critical | SSRF-prone URL | Private network targets, cloud metadata endpoints, reserved addresses, or dangerous URL schemes |
| MCP010 | high-critical | OAuth or token risk | OAuth/bearer credentials, broad scopes, unsafe OAuth URLs, token query strings, or weak PKCE metadata |
| MCP011 | medium-high | Transport hardening gap | Local HTTP hardening gaps, wildcard network binds, or wildcard browser origins |
| MCP012 | high | TLS verification disabled | Flags, environment variables, or settings that disable certificate verification or secure transport enforcement |
| MCP013 | medium-high | Automatic tool approval | Non-empty `alwaysAllow`/`autoApprove` settings that bypass per-call confirmation for named or wildcard tools |

`MCP003` recognizes environment and password-input references such as `${TOKEN}`, `Bearer ${TOKEN}`, and Codex `bearer_token_env_var`; those references are not reported as literal credentials.

## Evidence and Severity Rationale

Last reviewed: 2026-07-22.

- `MCP003` is critical because a literal credential is immediately reusable outside the MCP client. This follows [OWASP MCP01 guidance](https://owasp.org/www-project-mcp-top-10/2025/MCP01-2025-Token-Mismanagement-and-Secret-Exposure) to detect hard-coded tokens in client and server configuration.
- `MCP007` is high because model-facing metadata is an instruction surface. Invisible Unicode controls receive high confidence because they conceal text without adding a normal description capability.
- `MCP010` treats wildcard and omnibus scopes as high risk, following the MCP specification's [scope-minimization guidance](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices#scope-minimization).
- `MCP011` and `MCP012` are high when configuration exposes the service broadly or disables endpoint identity checks. The MCP [security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) require hardened local HTTP access and HTTPS for production authorization endpoints.
- `MCP013` is medium for named tools and high for wildcard approval. Named pre-approval can be reasonable for audited read-only operations, but wildcard approval removes a consent boundary. The [NSA MCP security guidance](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF) identifies poor approval workflows as a systemic risk, and [VS Code's approval guidance](https://code.visualstudio.com/docs/agents/approvals) warns that broad auto-approval bypasses critical protections.

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
