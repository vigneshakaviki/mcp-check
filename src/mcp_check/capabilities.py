from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .models import Finding, ServerConfig
from .rules.helpers import all_text_parts, is_placeholder, urls_in_text


def summarize_capabilities(servers: Iterable[ServerConfig], findings: Iterable[Finding]) -> Dict[str, Any]:
    server_list = list(servers)
    finding_list = list(findings)
    summary: Dict[str, Any] = {
        "shell": _has_rule(finding_list, "MCP001"),
        "filesystem": _evidence(finding_list, "MCP002"),
        "secrets": _locations(finding_list, "MCP003"),
        "network": _urls(server_list),
        "packages": _package_invocations(server_list),
        "docker": _has_docker(server_list) or _has_rule(finding_list, "MCP008"),
        "oauth": _has_rule(finding_list, "MCP010"),
        "metadata_injection": _has_rule(finding_list, "MCP007"),
        "ssrf": _has_rule(finding_list, "MCP009"),
        "tls_verification_disabled": _has_rule(finding_list, "MCP012"),
        "automatic_tool_approval": _has_rule(finding_list, "MCP013"),
    }
    return summary


def _has_rule(findings: List[Finding], rule_id: str) -> bool:
    return any(finding.rule_id == rule_id for finding in findings)


def _evidence(findings: List[Finding], rule_id: str) -> List[str]:
    return sorted({finding.evidence for finding in findings if finding.rule_id == rule_id})


def _locations(findings: List[Finding], rule_id: str) -> List[str]:
    return sorted({"%s.%s" % (finding.server, finding.location) for finding in findings if finding.rule_id == rule_id})


def _urls(servers: List[ServerConfig]) -> List[str]:
    urls = set()
    for server in servers:
        for _, value in all_text_parts(server):
            if is_placeholder(value):
                continue
            urls.update(urls_in_text(value))
    return sorted(urls)


def _package_invocations(servers: List[ServerConfig]) -> List[str]:
    package_commands = {"npx", "npm", "uvx", "pip", "pipx", "bunx", "docker", "podman"}
    return sorted({
        " ".join([server.command] + server.args[:2]).strip()
        for server in servers
        if server.command.lower() in package_commands
    })


def _has_docker(servers: List[ServerConfig]) -> bool:
    return any(server.command.lower() in {"docker", "podman"} for server in servers)
