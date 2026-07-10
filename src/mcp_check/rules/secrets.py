from __future__ import annotations

import re

from ..models import ServerConfig
from .helpers import is_placeholder, make_finding, redact


SECRET_NAME = re.compile(r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|AUTH)", re.IGNORECASE)
SECRET_VALUE = re.compile(r"(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[0-9A-Z]{12,})")


def check_secrets(server: ServerConfig):
    findings = []
    for key, value in server.env.items():
        value_text = str(value)
        if SECRET_NAME.search(str(key)) and not is_placeholder(value_text) and not value_text.startswith("${"):
            findings.append(make_finding(
                server, "MCP003", "critical", "high",
                "Credential appears directly in MCP configuration",
                "%s=%s" % (key, redact(value_text)),
                "env.%s" % key,
                "Replace the value with an environment-variable reference and rotate the exposed credential.",
            ))
        elif SECRET_VALUE.search(value_text):
            findings.append(make_finding(
                server, "MCP003", "critical", "high",
                "Credential-like value appears in MCP configuration",
                redact(value_text),
                "env.%s" % key,
                "Remove and rotate the credential; load it from a secret manager or environment-variable reference.",
            ))
    return findings
