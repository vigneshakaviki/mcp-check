from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import ServerConfig
from .helpers import all_text_parts, is_placeholder, make_finding, unique_findings


SECRET_ENV_NAME = re.compile(
    r"(?:^|_)(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_?KEY|AUTHORIZATION|AUTH|PAT)$",
    re.IGNORECASE,
)
SECRET_FIELD_NAME = re.compile(
    r"^(?:api_?key|access_?token|refresh_?token|id_?token|bearer_?token|client_?secret|password|passwd|"
    r"private_?key|secret|token|authorization|proxy_?authorization|x_?api_?key)$",
    re.IGNORECASE,
)
SECRET_VALUE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[0-9A-Z]{12,})"
)
BEARER_VALUE = re.compile(r"\bBearer\s+([^\s,;]+)", re.IGNORECASE)
SECRET_FLAGS = {
    "--api-key",
    "--apikey",
    "--access-token",
    "--auth-token",
    "--bearer-token",
    "--client-secret",
    "--password",
    "--secret",
    "--token",
}
TEMPLATE_REFERENCE = re.compile(r"\$\{[^}]+\}|%[A-Za-z_][A-Za-z0-9_]*%")
SYMBOLIC_REFERENCE = re.compile(r"^[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PAT)$")
REFERENCE_CONTAINERS = ("env_http_headers.",)


def check_secrets(server: ServerConfig):
    findings = []

    for key, value in server.env.items():
        value_text = str(value)
        if SECRET_ENV_NAME.search(str(key)) and not _is_secret_reference(value_text):
            findings.append(_secret_finding(server, "env.%s" % key, str(key)))

    for location, value in all_text_parts(server):
        if _is_reference_location(location) or _is_secret_reference(value):
            continue

        field_name = _field_name(location)
        if SECRET_FIELD_NAME.match(field_name) and not location.startswith("env."):
            findings.append(_secret_finding(server, location, field_name))
            continue

        if SECRET_VALUE.search(value):
            findings.append(_secret_finding(server, location, "credential-like value"))
            continue

        bearer = BEARER_VALUE.search(value)
        if bearer and not _is_secret_reference(bearer.group(1)):
            findings.append(_secret_finding(server, location, "bearer credential"))

        parsed = urlparse(value)
        if parsed.scheme in {"http", "https"} and parsed.username is not None:
            findings.append(make_finding(
                server, "MCP003", "critical", "high",
                "Credential appears in MCP URL user information",
                "%s://[redacted]@%s" % (parsed.scheme, parsed.hostname or "host"),
                location,
                "Remove credentials from the URL, rotate them, and use the client's environment-backed "
                "authentication support.",
            ))

    for index, argument in enumerate(server.args):
        lowered = argument.lower()
        if lowered in SECRET_FLAGS and index + 1 < len(server.args):
            candidate = server.args[index + 1]
            if not _is_secret_reference(candidate):
                findings.append(_secret_finding(server, "args[%d]" % (index + 1), argument))
        elif any(lowered.startswith(flag + "=") for flag in SECRET_FLAGS):
            candidate = argument.split("=", 1)[1]
            if not _is_secret_reference(candidate):
                findings.append(_secret_finding(server, "args[%d]" % index, argument.split("=", 1)[0]))

    return unique_findings(findings)


def _field_name(location: str) -> str:
    return location.rsplit(".", 1)[-1].split("[", 1)[0].replace("-", "_")


def _is_reference_location(location: str) -> bool:
    return location == "bearer_token_env_var" or location.startswith(REFERENCE_CONTAINERS)


def _is_secret_reference(value: str) -> bool:
    if is_placeholder(value):
        return True
    stripped = value.strip()
    if SYMBOLIC_REFERENCE.match(stripped):
        return True
    without_templates = TEMPLATE_REFERENCE.sub("", stripped)
    without_wrapper = re.sub(
        r"^(?:authorization\s*:\s*)?(?:bearer|basic)\s*",
        "",
        without_templates,
        flags=re.IGNORECASE,
    )
    return not without_wrapper.strip()


def _secret_finding(server: ServerConfig, location: str, label: str):
    return make_finding(
        server, "MCP003", "critical", "high",
        "Credential appears directly in MCP configuration",
        "%s=[redacted]" % label,
        location,
        "Replace the value with an environment or password-input reference, rotate the exposed credential, "
        "and keep it out of shared configuration.",
    )
