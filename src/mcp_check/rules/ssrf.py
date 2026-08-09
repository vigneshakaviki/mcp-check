from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from ..models import ServerConfig
from .helpers import all_text_parts, is_placeholder, make_finding, unique_findings, urls_in_text


DANGEROUS_SCHEMES = {"javascript", "data", "file", "vbscript"}
CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
}
CLOUD_METADATA_IPS = {"169.254.169.254"}
LOCAL_NAMES = {"localhost", "localtest.me"}
OCTAL_OCTET = re.compile(r"^0[0-7]+$")
HEX_OCTET = re.compile(r"^0[xX][0-9a-fA-F]+$")
DECIMAL_OCTET = re.compile(r"^(?:0|[1-9][0-9]*)$")
WHOLE_DECIMAL_ADDRESS = re.compile(r"^[0-9]{7,10}$")
WHOLE_HEX_ADDRESS = re.compile(r"^0[xX][0-9a-fA-F]{6,8}$")


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
            elif _is_cloud_metadata(host):
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


def _is_cloud_metadata(host: str) -> bool:
    if host in CLOUD_METADATA_HOSTS:
        return True
    address = _parse_ip(host)
    return address is not None and str(address) in CLOUD_METADATA_IPS


def _is_private_or_reserved(host: str) -> bool:
    address = _parse_ip(host)
    if address is None:
        return False
    return any((
        address.is_loopback,
        address.is_private,
        address.is_link_local,
        address.is_reserved,
        address.is_multicast,
        address.is_unspecified,
    ))


def _parse_ip(host: str):
    stripped = host.strip("[]")
    try:
        return ipaddress.ip_address(stripped)
    except ValueError:
        return _decode_obfuscated_ipv4(stripped)


def _decode_obfuscated_ipv4(host: str):
    # Bypass class where 127.0.0.1 (or another private/metadata address) is written as a
    # single decimal/hex integer or as dotted octets with octal/hex encoding, which
    # ipaddress.ip_address() rejects but common HTTP clients and resolvers still accept.
    # See OWASP SSRF Prevention Cheat Sheet and CVE-class "IPFuscation" bypass writeups.
    if WHOLE_DECIMAL_ADDRESS.match(host):
        try:
            return ipaddress.IPv4Address(int(host))
        except ValueError:
            return None
    if WHOLE_HEX_ADDRESS.match(host):
        try:
            return ipaddress.IPv4Address(int(host, 16))
        except ValueError:
            return None

    parts = host.split(".")
    if len(parts) != 4:
        return None
    if all(DECIMAL_OCTET.match(part) for part in parts):
        return None  # plain decimal dotted-quad is already handled by ipaddress.ip_address

    octets = [_decode_ip_octet(part) for part in parts]
    if any(value is None or not 0 <= value <= 255 for value in octets):
        return None
    try:
        return ipaddress.IPv4Address(".".join(str(value) for value in octets))
    except ValueError:
        return None


def _decode_ip_octet(token: str):
    if HEX_OCTET.match(token):
        return int(token, 16)
    if OCTAL_OCTET.match(token):
        return int(token, 8)
    if DECIMAL_OCTET.match(token):
        return int(token)
    return None
