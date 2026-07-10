from __future__ import annotations

import re

from ..models import ServerConfig
from .helpers import is_placeholder, make_finding, text_parts


URL = re.compile(r"https?://([^/\s]+)", re.IGNORECASE)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def check_network_access(server: ServerConfig):
    findings = []
    for location, value in text_parts(server):
        if is_placeholder(value):
            continue
        match = URL.search(value)
        if not match:
            continue
        host = match.group(1).split(":", 1)[0].lower()
        if value.lower().startswith("http://") and host not in LOCAL_HOSTS:
            findings.append(make_finding(
                server, "MCP005", "high", "high",
                "MCP server uses an insecure remote URL",
                value,
                location,
                "Use HTTPS for remote MCP servers and verify the server identity before connecting.",
            ))
        elif host not in LOCAL_HOSTS and location != "url":
            findings.append(make_finding(
                server, "MCP006", "medium", "medium",
                "MCP server configuration includes remote network access",
                value,
                location,
                "Confirm the destination is required, trusted, and constrained by network policy.",
            ))
    return findings
