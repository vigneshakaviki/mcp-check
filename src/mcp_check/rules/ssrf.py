from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from ..models import ServerConfig
from .helpers import all_text_parts, is_placeholder, make_finding, unique_findings, urls_in_text


DANGEROUS_SCHEMES = {"javascript", "data", "file", "vbscript"}
CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
}
LOCAL_NAMES = {"localhost", "localtest.me"}


def check_ssrf_targets(server: ServerConfig):
    findings = []
    for location, value in all_text_parts(server):
        if is_placeholder(value):
            continue
        for url in urls_in_text(value):
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower()
            if location == "url" and _is_local_transport_url(scheme, host):
                continue
            if scheme in DANGEROUS_SCHEMES:
                findings.append(make_finding(
                    server, "MCP009", "critical", "high",
                    "MCP configuration contains a dangerous URL scheme",
                    url,
                    location,
                    "Reject javascript:, data:, file:, and similar URL schemes in MCP authorization or metadata fields.",
                ))
            elif host in CLOUD_METADATA_HOSTS:
                findings.append(make_finding(
                    server, "MCP009", "critical", "high",
                    "MCP configuration references a cloud metadata endpoint",
                    url,
                    location,
                    "Block cloud metadata endpoints from MCP server, OAuth, and tool URLs.",
                ))
            elif host in LOCAL_NAMES or _is_private_or_reserved(host):
                findings.append(make_finding(
                    server, "MCP009", "high", "high",
                    "MCP configuration references a local or private network URL",
                    url,
                    location,
                    "Avoid routing MCP, OAuth, or tool requests to loopback, link-local, private, or reserved network addresses unless explicitly isolated.",
                ))
    return unique_findings(findings)


def _is_local_transport_url(scheme: str, host: str) -> bool:
    return scheme in {"http", "https"} and (host in LOCAL_NAMES or host in {"127.0.0.1", "::1"})


def _is_private_or_reserved(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return any((
        address.is_loopback,
        address.is_private,
        address.is_link_local,
        address.is_reserved,
        address.is_multicast,
        address.is_unspecified,
    ))
