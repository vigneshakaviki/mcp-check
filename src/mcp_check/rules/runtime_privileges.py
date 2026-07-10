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

    return unique_findings(findings)
