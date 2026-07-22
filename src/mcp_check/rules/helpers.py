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
    return [(path, value) for path, value in all_value_parts(server) if isinstance(value, str)]


def all_value_parts(server: ServerConfig) -> List[Tuple[str, Any]]:
    parts: List[Tuple[str, Any]] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, (str, int, float, bool)) or value is None:
            parts.append((path, value))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, "%s[%d]" % (path, index))
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(item, "%s.%s" % (path, key) if path else str(key))

    walk(server.data, "")
    return parts


URL_PATTERN = re.compile(r"\b(?:https?|file|data|javascript|vbscript):[^\s\"'<>),]+", re.IGNORECASE)


def urls_in_text(value: str) -> List[str]:
    return [match.group(0).rstrip("].}") for match in URL_PATTERN.finditer(value)]


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
    normalized = value.strip().lower()
    if bool(re.match(r"^\$\{[^}]+\}$", value)):
        return True
    if normalized in {"", "...", "changeme", "change-me", "your-key", "<secret>", "<token>", "<api-key>"}:
        return True
    return any(marker in normalized for marker in (
        "your_",
        "your-",
        "your ",
        "paste_your",
        "replace_me",
        "replace-me",
    ))
