---
title: "MCP Security Starts Before Server Startup"
description: "Why teams should scan MCP configs and SKILL.md bundles before granting an agent shell, network, filesystem, or credential access."
slug: scan-mcp-configs-before-they-run
keywords:
  - MCP security scanner
  - Model Context Protocol security
  - MCP configuration security
  - MCP tool poisoning
  - AI agent security
---

# MCP Security Starts Before Server Startup

MCP servers can give an AI agent access to shell commands, local files, cloud credentials, internal services, and third-party APIs. That power often enters a project through a short configuration file or a copied `SKILL.md` bundle.

Reviewing those files before they run is one of lowest-friction controls available to an engineering team.

`mcp-check` is an offline static scanner for MCP configuration files and skill bundles. It finds risky commands, embedded credentials, mutable installs, dangerous network targets, prompt-injection language, weak transport settings, and approval bypasses—without starting a server or sending config contents to an external service.

## MCP configuration is executable trust

An MCP config does more than point to a tool. It can specify:

- command to launch
- package or container image to install
- environment variables to pass
- local directories to mount
- remote endpoint to contact
- OAuth scopes and credentials
- tools to auto-approve

Each field can change what an agent can access. A harmless-looking addition can turn into arbitrary local code execution, secret exposure, or network access when client starts.

Example:

```json
{
  "mcpServers": {
    "docs-helper": {
      "command": "npx",
      "args": ["-y", "some-mcp-server"],
      "env": {
        "NODE_OPTIONS": "--require ./bootstrap.js"
      }
    }
  }
}
```

Package is mutable. `NODE_OPTIONS` can load code before server begins. A reviewer needs to spot both facts before approving config.

## Why this matters now

Public MCP guidance calls out local-server compromise, untrusted metadata, OAuth scope minimization, SSRF, and DNS-rebinding risks. OWASP also names tool poisoning, scope creep, supply-chain tampering, command execution, and prompt injection as core MCP risks. These are not separate problems: one unreviewed integration can combine them.

Academic research makes same point from another direction. [MCPTox](https://arxiv.org/abs/2508.14925) evaluates tool-poisoning attacks across real MCP servers. [Systematic Analysis of MCP Security](https://arxiv.org/abs/2508.12538) describes attacks spanning direct tool injection, indirect context injection, malicious users, and model behavior. Static review cannot solve every runtime attack, but it can prevent obvious dangerous configuration from reaching runtime.

## What mcp-check catches before startup

Run one command against JSON, YAML, or TOML:

```bash
python -m pip install mcp-check-security
mcp-check scan ./.vscode/mcp.json
```

Or scan an agent skill bundle before enabling it:

```bash
mcp-check scan-skill ./skills/vendor-skill
```

Checks include:

| Review question | mcp-check signal |
| --- | --- |
| Does config run risky shell code? | Privileged, destructive, download-and-execute, and dynamic execution patterns |
| Does it expose credentials? | Literal tokens in environment values, headers, URLs, nested auth fields, and arguments |
| Is dependency source mutable? | Unpinned packages, Git references, and container images |
| Can it reach sensitive networks? | Cloud metadata endpoints, local/private/reserved IP ranges, and dangerous URL schemes |
| Does metadata try to steer agent? | Prompt-injection language and invisible Unicode controls |
| Is transport hardened? | Plain HTTP, wildcard binds/origins, disabled TLS verification |
| Does client skip approval? | Named or wildcard auto-approval settings |

Results work in terminal output, JSON, and SARIF. Teams can use SARIF for pull-request review and baseline existing findings while blocking new high-severity risk.

## Keep scanner offline on purpose

Many security tools need a live endpoint, package install, or runtime instrumentation. Those are useful controls, but they happen after trust decision has already moved forward.

`mcp-check` stays offline:

- no server launch
- no network connection
- no code execution
- no config upload

That makes it fit early review: before a developer runs copied config, before a skill bundle is enabled, and before a pull request merges.

## Add MCP review to pull requests

Use GitHub Action in CI:

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
            ./.vscode/mcp.json
            ./.codex/config.toml
```

Start with report-only mode. Fix critical findings, add narrowly documented suppressions for accepted exceptions, then gate new high-severity findings. This avoids blocking adoption while making new risk visible.

## Static scanning has boundaries

No static scanner can prove remote server behavior stays safe. Tool descriptions can change after approval, DNS can rebind after validation, and tool output can carry prompt injection at runtime. MCP guidance recommends runtime controls such as tight OAuth scopes, per-client consent, redirect validation, network policy, and sandboxing.

Use static scanning as first gate, then layer runtime controls behind it. This is defense in depth, not a claim that one command makes an agent safe.

## Scan before approving access

MCP makes powerful integrations easy to add. Security review should be equally easy.

Start with current MCP configs and skill bundles:

```bash
mcp-check scan --preset all
mcp-check scan-skill ./skills/vendor-skill
```

Read [rule reference](../rules.md), add [GitHub Action scanning](../github-action.md), and review [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) before granting an agent more access.
