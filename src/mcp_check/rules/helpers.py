from __future__ import annotations

import re
from typing import Any, Iterable, List, Tuple

from ..models import Finding, ServerConfig


def text_parts(server: ServerConfig) -> List[Tuple[str, str]]:
    parts = [("command", server.command)]
    parts.extend(("args[%d]" % index, value) for index, value in enumerate(server.args))
    if server.url:
        parts.append(("url", server.url))
    parts.extend(("env.%s" % key, str(value)) for key, value in server.env.items())
    return parts


def all_text_parts(server: ServerConfig) -> List[Tuple[str, str]]:
    parts: List[Tuple[str, str]] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, str):
            parts.append((path, value))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, "%s[%d]" % (path, index))
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(item, "%s.%s" % (path, key) if path else str(key))

    walk(server.data, "")
    return parts


def make_finding(
    server: ServerConfig,
    rule_id: str,
    severity: str,
    confidence: str,
    title: str,
    evidence: str,
    location: str,
    recommendation: str,
) -> Finding:
    return Finding(rule_id, severity, confidence, title, evidence, location, recommendation, server.name)


def redact(value: str) -> str:
    if len(value) <= 8:
        return "[redacted]"
    return value[:4] + "..." + value[-2:]


def unique_findings(findings: Iterable[Finding]) -> List[Finding]:
    seen = set()
    result = []
    for finding in findings:
        key = (finding.rule_id, finding.server, finding.location)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def is_placeholder(value: str) -> bool:
    return bool(re.match(r"^\$\{[^}]+\}$", value)) or value.lower() in {"", "changeme", "your-key", "<secret>"}
