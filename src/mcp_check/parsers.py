from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .models import ServerConfig

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 and below
    import tomli as tomllib  # type: ignore[no-redef]


class ConfigError(ValueError):
    """Raised when an MCP configuration cannot be scanned safely."""


def _load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency is declared
        raise ConfigError("YAML support requires PyYAML to be installed") from exc

    try:
        with path.open("r", encoding="utf-8") as handle:
            value = yaml.safe_load(handle)
    except OSError as exc:
        raise ConfigError("could not read %s: %s" % (path, exc)) from exc
    except yaml.YAMLError as exc:
        raise ConfigError("invalid YAML in %s: %s" % (path, exc)) from exc
    return _ensure_object(value, path)


def _load_toml(path: Path) -> Dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError("could not read %s: %s" % (path, exc)) from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError("invalid TOML in %s: %s" % (path, exc)) from exc
    return _ensure_object(value, path)


def _ensure_object(value: Any, path: Path) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError("configuration root must be a JSON/YAML/TOML object")
    return value


def load_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise ConfigError("configuration file does not exist: %s" % path)

    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        return _load_yaml(path)
    if suffix == ".toml":
        return _load_toml(path)

    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError("configuration file does not exist: %s" % path) from exc
    except json.JSONDecodeError as exc:
        raise ConfigError("invalid JSON at line %d column %d: %s" % (exc.lineno, exc.colno, exc.msg)) from exc
    except OSError as exc:
        raise ConfigError("could not read %s: %s" % (path, exc)) from exc

    return _ensure_object(value, path)


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
