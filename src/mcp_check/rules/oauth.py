from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import ServerConfig
from .helpers import all_text_parts, is_placeholder, make_finding, redact, unique_findings, urls_in_text


TOKEN_KEY = re.compile(r"(?:ACCESS|BEARER|REFRESH|ID|OAUTH|AUTH).*(?:TOKEN|SECRET)|CLIENT_SECRET", re.IGNORECASE)
BROAD_SCOPE = re.compile(r"(?:^|\s|[,])(?:\*|admin(?::\*)?|files:\*|repo(?::\*)?|write:\*|read:\*)($|\s|[,])", re.IGNORECASE)
AUTH_LOCATION = re.compile(r"(?:authorization_endpoint|token_endpoint|issuer|jwks_uri|redirect_uri|callback|oauth)", re.IGNORECASE)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def check_oauth_config(server: ServerConfig):
    findings = []
    for key, value in server.env.items():
        value_text = str(value)
        if TOKEN_KEY.search(str(key)) and not is_placeholder(value_text) and not value_text.startswith("${"):
            findings.append(make_finding(
                server, "MCP010", "critical", "high",
                "OAuth or bearer credential appears directly in MCP configuration",
                "%s=%s" % (key, redact(value_text)),
                "env.%s" % key,
                "Load OAuth tokens and client secrets from a secret manager or environment variable reference, then rotate exposed values.",
            ))

    for location, value in all_text_parts(server):
        if is_placeholder(value):
            continue
        lowered_location = location.lower()
        if ("scope" in lowered_location or "scopes" in lowered_location) and BROAD_SCOPE.search(value):
            findings.append(make_finding(
                server, "MCP010", "high", "medium",
                "MCP configuration requests broad OAuth scopes",
                value,
                location,
                "Request the smallest OAuth scopes needed for the server and avoid wildcard or admin scopes.",
            ))
        if not AUTH_LOCATION.search(location):
            continue
        for url in urls_in_text(value):
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower()
            if scheme not in {"http", "https"}:
                findings.append(make_finding(
                    server, "MCP010", "critical", "high",
                    "OAuth URL uses a dangerous scheme",
                    url,
                    location,
                    "Only allow http:// loopback development URLs or https:// OAuth endpoints.",
                ))
            elif scheme == "http" and host not in LOCAL_HOSTS:
                findings.append(make_finding(
                    server, "MCP010", "high", "high",
                    "OAuth URL does not use HTTPS",
                    url,
                    location,
                    "Use HTTPS for authorization, token, issuer, JWKS, and non-loopback redirect URLs.",
                ))
    return unique_findings(findings)
