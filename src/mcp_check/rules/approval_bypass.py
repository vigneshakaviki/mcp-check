from __future__ import annotations

import re
from typing import Any

from ..models import ServerConfig
from .helpers import make_finding, unique_findings


AUTO_APPROVE_FIELDS = {"always_allow", "auto_approve", "autoapprove", "trust"}


def check_approval_bypass(server: ServerConfig):
    findings = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                location = "%s.%s" % (path, key) if path else str(key)
                normalized_key = _snake_case(str(key))
                if normalized_key in AUTO_APPROVE_FIELDS and _is_enabled(item):
                    wildcard = _is_wildcard(item)
                    if normalized_key == "trust":
                        title = "MCP server bypasses all tool-call approval"
                        recommendation = (
                            "Remove the server-level trust flag and require per-call confirmation; "
                            "reserve trust for servers you fully control and have already audited."
                        )
                    else:
                        title = "MCP tools can run without per-call approval"
                        recommendation = (
                            "Remove broad auto-approval and require confirmation for mutating, external, or "
                            "sensitive tools; pre-approve only narrowly reviewed read-only operations."
                        )
                    findings.append(make_finding(
                        server, "MCP013", "high" if wildcard else "medium", "high",
                        title,
                        _evidence(str(key), item),
                        location,
                        recommendation,
                    ))
                walk(item, location)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, "%s[%d]" % (path, index))

    walk(server.data, "")
    return unique_findings(findings)


def _snake_case(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return value.replace("-", "_").lower()


def _is_enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, list):
        return bool(value)
    if isinstance(value, dict):
        return any(_is_enabled(item) for item in value.values())
    return str(value).strip().lower() not in {"", "0", "false", "no", "off", "none"}


def _is_wildcard(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, list):
        return any(str(item).strip().lower() in {"*", "all"} for item in value)
    if isinstance(value, dict):
        return any(
            str(key).strip().lower() in {"*", "all"} and _is_enabled(item)
            for key, item in value.items()
        )
    return str(value).strip().lower() in {"*", "all", "true", "1", "yes", "on"}


def _evidence(field: str, value: Any) -> str:
    if isinstance(value, list):
        suffix = " including wildcard access" if _is_wildcard(value) else ""
        return "%s enables %d tool(s)%s" % (field, len(value), suffix)
    if isinstance(value, dict):
        enabled = sum(1 for item in value.values() if _is_enabled(item))
        return "%s enables %d approval rule(s)" % (field, enabled)
    return "%s=%s" % (field, value)
