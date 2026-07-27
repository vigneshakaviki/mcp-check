from __future__ import annotations

import re

from ..models import ServerConfig
from .helpers import all_value_parts, make_finding, unique_findings


DISABLED_VERIFY_ENV = {
    "GIT_SSL_NO_VERIFY": {"1", "true", "yes", "on"},
    "NODE_TLS_REJECT_UNAUTHORIZED": {"0", "false", "no", "off"},
    "NPM_CONFIG_STRICT_SSL": {"0", "false", "no", "off"},
    "PYTHONHTTPSVERIFY": {"0", "false", "no", "off"},
}
INSECURE_FLAGS = {
    "--allow-insecure",
    "--disable-tls-verification",
    "--insecure",
    "--no-check-certificate",
    "--no-verify-ssl",
    "--skip-tls-verify",
    "--tls-skip-verify",
}
NEGATIVE_KEYS = {
    "check_certificate",
    "reject_unauthorized",
    "ssl_verify",
    "strict_ssl",
    "tls_verify",
    "verify_certificate",
    "verify_ssl",
    "verify_tls",
}
POSITIVE_KEYS = {
    "allow_insecure",
    "dangerously_allow_http",
    "disable_tls_verification",
    "insecure_skip_verify",
    "skip_tls_verify",
    "tls_insecure",
}


def check_tls_security(server: ServerConfig):
    findings = []

    for location, value in all_value_parts(server):
        normalized_location = _snake_case(location)
        field_name = normalized_location.rsplit(".", 1)[-1].split("[", 1)[0]
        normalized_value = str(value).strip().lower()

        env_name = location[4:] if location.startswith("env.") else ""
        if env_name in DISABLED_VERIFY_ENV and normalized_value in DISABLED_VERIFY_ENV[env_name]:
            findings.append(_finding(server, location, "%s=%s" % (env_name, value)))
        elif field_name in NEGATIVE_KEYS and _is_false(value):
            findings.append(_finding(server, location, "%s=%s" % (field_name, value)))
        elif field_name in POSITIVE_KEYS and _is_true(value):
            findings.append(_finding(server, location, "%s=%s" % (field_name, value)))

    for index, argument in enumerate(server.args):
        normalized = argument.lower()
        inline_disabled = any(
            normalized.startswith(flag + "=") and _is_true(normalized.split("=", 1)[1])
            for flag in INSECURE_FLAGS
        )
        if normalized in INSECURE_FLAGS or inline_disabled:
            findings.append(_finding(server, "args[%d]" % index, argument))

    return unique_findings(findings)


def _snake_case(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return value.replace("-", "_").lower()


def _is_false(value) -> bool:
    return value is False or str(value).strip().lower() in {"0", "false", "no", "off"}


def _is_true(value) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _finding(server: ServerConfig, location: str, evidence: str):
    return make_finding(
        server, "MCP012", "high", "high",
        "TLS certificate verification is disabled",
        evidence,
        location,
        "Enable certificate verification and use a trusted CA bundle; do not weaken TLS checks to make an "
        "MCP endpoint connect.",
    )
