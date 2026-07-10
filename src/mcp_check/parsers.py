from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .models import ServerConfig


class ConfigError(ValueError):
    """Raised when an MCP configuration cannot be scanned safely."""


def load_config(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError("configuration file does not exist: %s" % path) from exc
    except json.JSONDecodeError as exc:
        raise ConfigError("invalid JSON at line %d column %d: %s" % (exc.lineno, exc.colno, exc.msg)) from exc
    except OSError as exc:
        raise ConfigError("could not read %s: %s" % (path, exc)) from exc

    if not isinstance(value, dict):
        raise ConfigError("configuration root must be a JSON object")
    return value


def parse_servers(config: Dict[str, Any]) -> List[ServerConfig]:
    raw_servers = config.get("mcpServers")
    if raw_servers is None:
        raise ConfigError("configuration must contain an object named 'mcpServers'")
    if not isinstance(raw_servers, dict):
        raise ConfigError("'mcpServers' must be a JSON object")

    servers = []
    for name, data in raw_servers.items():
        if not isinstance(name, str) or not name.strip():
            raise ConfigError("every MCP server must have a non-empty name")
        if not isinstance(data, dict):
            raise ConfigError("server %r must be a JSON object" % name)
        servers.append(ServerConfig(name=name, data=data))
    return servers
