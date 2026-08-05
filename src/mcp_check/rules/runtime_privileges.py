from __future__ import annotations

import re

from ..models import ServerConfig
from .helpers import make_finding, text_parts, unique_findings


PRIVILEGED_FLAGS = {"--privileged", "--cap-add=SYS_ADMIN", "--cap-add=ALL"}
HOST_FLAGS = {"--net=host", "--network=host", "--pid=host", "--ipc=host"}
DOCKER_SOCKET = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
BROAD_MOUNT = re.compile(
    r"(?:^|[=:\s])(?:/|~|/Users|/home|/var|/private|/etc)(?::|$)",
    re.IGNORECASE,
)
ENV_WILDCARD = re.compile(r"(?:--env-file\s+\S+|--env\s+\*|\benv\s+\*)", re.IGNORECASE)

# Dynamic-linker and language-runtime variables that load attacker-controlled code into
# the spawned MCP server process. See GHSA-mj59-h3q9-ghfh (workspace MCP stdio config
# passing NODE_OPTIONS/LD_PRELOAD/BASH_ENV to the child process) and MITRE ATT&CK T1574.006.
DANGEROUS_ENV_VARS = {
    "LD_PRELOAD": "critical",
    "DYLD_INSERT_LIBRARIES": "critical",
    "LD_LIBRARY_PATH": "high",
    "DYLD_LIBRARY_PATH": "high",
    "DYLD_FRAMEWORK_PATH": "high",
    "NODE_OPTIONS": "high",
    "PYTHONPATH": "high",
    "PERL5OPT": "high",
    "RUBYOPT": "high",
    "BASH_ENV": "high",
    "JAVA_TOOL_OPTIONS": "high",
}


def check_runtime_privileges(server: ServerConfig):
    findings = []
    values = [value for _, value in text_parts(server)]
    joined = " ".join(values)
    lowered = {value.lower() for value in values}

    if any(flag.lower() in lowered or flag.lower() in joined.lower() for flag in PRIVILEGED_FLAGS):
        findings.append(make_finding(
            server, "MCP008", "critical", "high",
            "MCP server requests privileged container execution",
            joined[:180],
            "args.privileged",
            "Remove privileged container flags and grant only the specific capability the server requires.",
        ))

    if any(flag in joined.lower() for flag in HOST_FLAGS):
        findings.append(make_finding(
            server, "MCP008", "high", "high",
            "MCP server requests host namespace access",
            joined[:180],
            "args.host_namespace",
            "Avoid host network, PID, or IPC namespaces unless the server is fully trusted and isolated.",
        ))

    if DOCKER_SOCKET.search(joined):
        findings.append(make_finding(
            server, "MCP008", "critical", "high",
            "MCP server mounts the Docker socket",
            "/var/run/docker.sock",
            "args.docker_socket",
            "Do not mount the host Docker socket into MCP servers; use a narrow broker or isolated runtime.",
        ))

    for location, value in text_parts(server):
        if location.startswith("env."):
            continue
        if ("-v" in values or "--volume" in values or "--mount" in values) and BROAD_MOUNT.search(value):
            findings.append(make_finding(
                server, "MCP008", "high", "medium",
                "MCP server mounts a broad host path",
                value,
                "%s.mount" % location,
                "Mount the smallest project directory needed and make read-only mounts explicit where possible.",
            ))
        if ENV_WILDCARD.search(value):
            findings.append(make_finding(
                server, "MCP008", "medium", "medium",
                "MCP server may inherit broad environment variables",
                value,
                location,
                "Pass only the specific environment variables required by the server.",
            ))

    for key, value in server.env.items():
        severity = DANGEROUS_ENV_VARS.get(str(key).upper())
        if severity and str(value).strip():
            findings.append(make_finding(
                server, "MCP008", severity, "high",
                "MCP server sets a code-injection environment variable",
                "%s=%s" % (key, str(value)[:120]),
                "env.%s" % key,
                "Remove %s from the server environment unless it is required and the value is fully trusted; "
                "this variable can load attacker-controlled code into the spawned process." % key,
            ))

    return unique_findings(findings)
