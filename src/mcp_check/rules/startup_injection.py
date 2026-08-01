from __future__ import annotations

import re

from ..models import ServerConfig
from .helpers import is_placeholder, make_finding, unique_findings


# These environment variables are consumed by runtimes or shells before the
# configured MCP server starts.  Treating them as ordinary configuration can
# hide arbitrary code that runs with the MCP client's privileges.
DIRECT_LOADERS = {
    "LD_PRELOAD",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONSTARTUP",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
}
NODE_PRELOAD = re.compile(r"(?:^|\s)--(?:require|import|loader|experimental-loader)(?:=|\s|$)", re.IGNORECASE)
PYTHON_PATH_KEYS = {"PYTHONPATH", "PYTHONHOME"}


def check_startup_injection(server: ServerConfig):
    findings = []
    for key, value in server.env.items():
        name = str(key).upper()
        text = str(value).strip()
        if not text or is_placeholder(text):
            continue
        if name in DIRECT_LOADERS:
            findings.append(_finding(server, key, text, "runtime startup hook"))
        elif name == "NODE_OPTIONS" and NODE_PRELOAD.search(text):
            findings.append(_finding(server, key, text, "Node.js preload or loader option"))
        elif name in PYTHON_PATH_KEYS:
            findings.append(_finding(server, key, text, "Python module search-path override"))
    return unique_findings(findings)


def _finding(server: ServerConfig, key: object, value: str, mechanism: str):
    return make_finding(
        server, "MCP014", "high", "high",
        "MCP server environment can inject code at startup",
        "%s=%s (%s)" % (key, value[:160], mechanism),
        "env.%s" % key,
        "Remove runtime preload and startup-hook variables. Run the server with a minimal, explicit environment and review any required loader configuration.",
    )
