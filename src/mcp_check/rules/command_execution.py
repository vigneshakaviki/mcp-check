from __future__ import annotations

import re

from ..models import ServerConfig
from .helpers import make_finding, text_parts, unique_findings


PATTERNS = [
    (r"(^|\s)sudo(\s|$)", "privileged command", "critical"),
    (r"rm\s+-[^\n]*r[^\n]*f|rm\s+-rf", "recursive force deletion", "critical"),
    (r"(?:^|\s)(?:sh|bash|zsh|fish|powershell|cmd)(?:\s|$)", "shell interpreter", "high"),
    (r"(?:^|\s)(?:curl|wget)(?:\s|$)", "network download command", "high"),
    (r"\b(?:eval|exec)\s*\(|\$\([^)]*\)|`[^`]+`", "dynamic command execution", "high"),
]


def check_command_execution(server: ServerConfig):
    findings = []
    for location, value in text_parts(server):
        for pattern, label, severity in PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                findings.append(make_finding(
                    server, "MCP001", severity, "high",
                    "MCP server contains a %s" % label,
                    value,
                    location,
                    "Review the exact command and remove privileged, destructive, or downloaded execution unless it is required and trusted.",
                ))
                break
    return unique_findings(findings)
