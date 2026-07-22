from __future__ import annotations

from typing import Dict, List


RULE_CATALOG: List[Dict[str, str]] = [
    {
        "id": "MCP001",
        "severity": "high-critical",
        "title": "Dangerous command execution",
        "description": "Privileged, destructive, shell, download, or dynamic execution commands.",
    },
    {
        "id": "MCP002",
        "severity": "high",
        "title": "Sensitive local path",
        "description": "SSH keys, cloud credentials, environment files, home directories, and other sensitive paths.",
    },
    {
        "id": "MCP003",
        "severity": "critical",
        "title": "Embedded credential",
        "description": "Credentials or credential-like values embedded directly in MCP configuration.",
    },
    {
        "id": "MCP004",
        "severity": "medium-high",
        "title": "Mutable package or image",
        "description": "Unpinned packages, mutable Git refs, and mutable container images.",
    },
    {
        "id": "MCP005",
        "severity": "high",
        "title": "Insecure remote HTTP URL",
        "description": "Remote MCP URLs that use HTTP instead of HTTPS.",
    },
    {
        "id": "MCP006",
        "severity": "medium",
        "title": "Remote network access",
        "description": "Remote destinations in command arguments or environment values.",
    },
    {
        "id": "MCP007",
        "severity": "high",
        "title": "Prompt-injection metadata",
        "description": "Suspicious prompt-injection language in tool descriptions, prompts, annotations, or metadata.",
    },
    {
        "id": "MCP008",
        "severity": "high-critical",
        "title": "Dangerous runtime privileges",
        "description": "Privileged containers, host namespaces, Docker socket mounts, broad mounts, or broad environment inheritance.",
    },
    {
        "id": "MCP009",
        "severity": "high-critical",
        "title": "SSRF-prone URL",
        "description": "Private network targets, cloud metadata endpoints, reserved addresses, or dangerous URL schemes.",
    },
    {
        "id": "MCP010",
        "severity": "high-critical",
        "title": "OAuth or token risk",
        "description": "OAuth/bearer credentials, broad scopes, unsafe OAuth URLs, token query strings, or weak PKCE metadata.",
    },
    {
        "id": "MCP011",
        "severity": "medium-high",
        "title": "Transport hardening gap",
        "description": "Local HTTP transport hardening gaps, wildcard network binds, and wildcard browser origins.",
    },
    {
        "id": "MCP012",
        "severity": "high",
        "title": "TLS verification disabled",
        "description": "Flags, environment variables, or settings that disable certificate verification or secure transport enforcement.",
    },
    {
        "id": "MCP013",
        "severity": "medium-high",
        "title": "Automatic tool approval",
        "description": "Client settings that let named or wildcard MCP tools run without per-call confirmation.",
    },
]
