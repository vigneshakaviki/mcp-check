from __future__ import annotations

import re

from ..models import ServerConfig
from .helpers import make_finding, text_parts, unique_findings


SENSITIVE = re.compile(
    r"(?:~|/Users/[^\s]+|/home/[^\s]+|\.ssh|\.aws|\.config/gcloud|\.kube/config|\.env(?:\.|$)|id_rsa|id_ed25519|credentials\.json)",
    re.IGNORECASE,
)


def check_sensitive_paths(server: ServerConfig):
    findings = []
    for location, value in text_parts(server):
        if SENSITIVE.search(value):
            findings.append(make_finding(
                server, "MCP002", "high", "high",
                "MCP server references a sensitive local path",
                value,
                location,
                "Restrict access to the smallest project directory and never expose SSH keys, cloud credentials, or environment files.",
            ))
    return unique_findings(findings)
