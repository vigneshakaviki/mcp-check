from __future__ import annotations

import re

from ..models import ServerConfig
from .helpers import make_finding


def _is_pinned(package: str) -> bool:
    return bool(re.search(r"(?:==|@)v?\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?$", package))


def _is_commit_pinned(reference: str) -> bool:
    return bool(re.search(r"(?:#|@)[0-9a-f]{12,40}$", reference, re.IGNORECASE))


def _docker_image(args):
    value_options = {"-v", "--volume", "--mount", "-e", "--env", "--env-file", "-p", "--publish", "--name", "-w", "--workdir", "-u", "--user"}
    for index, arg in enumerate(args):
        if arg in {"run", "pull"}:
            skip_next = False
            for candidate in args[index + 1:]:
                if skip_next:
                    skip_next = False
                    continue
                if candidate in value_options:
                    skip_next = True
                    continue
                if candidate.startswith("-"):
                    continue
                return candidate
    return None


def _is_docker_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    if ":" not in image.rsplit("/", 1)[-1]:
        return False
    return not image.endswith(":latest")


def check_package_provenance(server: ServerConfig):
    command = server.command.lower()
    if command in {"docker", "podman"}:
        image = _docker_image(server.args)
        if image and not _is_docker_pinned(image):
            return [make_finding(
                server, "MCP004", "high", "medium",
                "MCP container image is not immutable",
                "%s %s" % (server.command, image),
                "args",
                "Pin container images by digest or a reviewed version tag instead of using mutable or implicit tags.",
            )]
        return []

    if command not in {"npx", "npm", "uvx", "pip", "pipx", "bunx"}:
        return []
    package = next(
        (item for item in server.args if not item.startswith("-") and item not in {"install", "run", "x"}),
        None,
    )
    if package is None:
        return []
    if re.search(r"(?:github\.com|git\+https?://|\.git(?:#|$))", package, re.IGNORECASE) and not _is_commit_pinned(package):
        return [make_finding(
            server, "MCP004", "high", "medium",
            "MCP package is installed from a mutable Git reference",
            "%s %s" % (server.command, package),
            "args",
            "Pin Git-based installs to a reviewed commit SHA and verify the repository owner.",
        )]
    if _is_pinned(package):
        return []
    return [make_finding(
        server, "MCP004", "medium", "medium",
        "MCP package is not version pinned",
        "%s %s" % (server.command, package),
        "args",
        "Pin the package to a reviewed version and prefer a trusted registry or immutable artifact.",
    )]
