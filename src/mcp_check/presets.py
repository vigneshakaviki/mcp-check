from __future__ import annotations

import platform
from pathlib import Path
from typing import Dict, List

from .parsers import ConfigError


def project_paths(root: Path) -> List[Path]:
    """Find known project configs, without walking parents or subprojects."""
    if not root.is_dir():
        raise ConfigError("project directory does not exist or is not a directory: %s" % root)
    candidates = [root / ".mcp.json", root / ".cursor" / "mcp.json", root / ".vscode" / "mcp.json"]
    paths = []
    for path in candidates:
        if path.exists() or path.is_symlink():
            if not path.is_file():
                raise ConfigError("project config is not a readable file: %s" % path)
            paths.append(path)
    return paths


def _home() -> Path:
    return Path.home()


def candidate_paths() -> Dict[str, List[Path]]:
    home = _home()
    system = platform.system().lower()
    paths = {
        "codex": [
            home / ".codex" / "config.toml",
        ],
        "copilot-cli": [
            home / ".copilot" / "mcp-config.json",
        ],
        "cursor": [
            home / ".cursor" / "mcp.json",
            home / ".cursor" / ".cursor-mcp.json",
        ],
        "claude-code": [
            home / ".claude.json",
            home / ".claude" / "mcp.json",
        ],
    }

    if system == "darwin":
        paths["claude-desktop"] = [
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        ]
    elif system == "windows":
        paths["claude-desktop"] = [
            home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
        ]
    else:
        paths["claude-desktop"] = [
            home / ".config" / "Claude" / "claude_desktop_config.json",
            home / ".config" / "claude" / "claude_desktop_config.json",
        ]

    paths["all"] = sorted({path for group in paths.values() for path in group})
    return paths


def existing_preset_paths(name: str) -> List[Path]:
    paths = candidate_paths()
    if name not in paths:
        raise KeyError(name)
    return [path for path in paths[name] if path.exists()]
