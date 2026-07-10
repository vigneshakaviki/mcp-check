from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import ServerConfig
from .helpers import all_text_parts, is_placeholder, make_finding, text_parts, unique_findings, urls_in_text


WILDCARD_BIND = re.compile(r"(?:^|[\s=:])(?:0\.0\.0\.0|\[?::\]?)(?:$|[\s:/])")
HOST_FLAGS = {"--host", "--listen", "--bind", "--addr", "--address"}
LOCAL_HTTP_HOSTS = {"localhost", "127.0.0.1", "::1"}


def check_transport_security(server: ServerConfig):
    findings = []
    if server.url:
        parsed = urlparse(server.url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "http" and host in LOCAL_HTTP_HOSTS:
            findings.append(make_finding(
                server, "MCP011", "medium", "medium",
                "Local HTTP MCP transport requires origin and auth hardening",
                server.url,
                "url",
                "For local HTTP MCP servers, bind to loopback only and require Origin validation plus authentication to reduce DNS rebinding risk.",
            ))

    parts = text_parts(server)
    values = [value for _, value in parts]
    for index, value in enumerate(values):
        if value in HOST_FLAGS and index + 1 < len(values) and values[index + 1] in {"0.0.0.0", "::", "[::]"}:
            findings.append(make_finding(
                server, "MCP011", "high", "high",
                "MCP server binds to all network interfaces",
                "%s %s" % (value, values[index + 1]),
                "args[%d]" % index,
                "Bind local MCP HTTP servers to localhost unless the server is intentionally exposed and protected by authentication and network policy.",
            ))

    for location, value in all_text_parts(server):
        if is_placeholder(value):
            continue
        if WILDCARD_BIND.search(value):
            findings.append(make_finding(
                server, "MCP011", "high", "medium",
                "MCP server references a wildcard network bind",
                value,
                location,
                "Avoid 0.0.0.0 or :: binds for local MCP servers unless the endpoint is authenticated and intentionally exposed.",
            ))
        for url in urls_in_text(value):
            parsed = urlparse(url)
            if parsed.hostname in {"0.0.0.0", "::"}:
                findings.append(make_finding(
                    server, "MCP011", "high", "high",
                    "MCP server URL uses a wildcard network address",
                    url,
                    location,
                    "Use a concrete host and protect exposed MCP HTTP endpoints with authentication and Origin validation.",
                ))
    return unique_findings(findings)
