"""Discover and scan local skill libraries without executing bundle content."""
from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from .aggregation import merge_results
from .baseline import diff_findings, load_signatures
from .models import ScanResult
from .parsers import ConfigError
from .skill_scanner import scan_skill


IGNORED_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__"}


def discover_skills(path: Path) -> list[Path]:
    if not path.is_dir():
        raise ConfigError("recursive skill scan requires a directory: %s" % path)

    def on_error(error: OSError) -> None:
        raise ConfigError("could not discover skills: %s" % error) from error

    skills = []
    for directory, dirs, files in os.walk(path, followlinks=False, onerror=on_error):
        root = Path(directory)
        dirs[:] = sorted(
            name for name in dirs
            if name not in IGNORED_DIRECTORIES and not (root / name).is_symlink()
        )
        if "SKILL.md" in files:
            skills.append(root)
    if not skills:
        raise ConfigError("no SKILL.md bundles found under %s" % path)
    return sorted(skills)


def scan_skill_library(
    path: Path, suppressions_path: Path | None = None, baseline_path: Path | None = None,
) -> ScanResult:
    results = [scan_skill(skill, suppressions_path) for skill in discover_skills(path)]
    result = replace(merge_results(results), source=str(path))
    if baseline_path is not None:
        baseline = load_signatures(baseline_path)
        # Legacy reports have no per-finding paths and cannot distinguish two
        # bundles with the same name. Refuse to hide findings using those reports.
        if any(not signature[-1] for signature in baseline):
            raise ConfigError("recursive skill baselines require per-finding sources; regenerate the baseline with --recursive")
        active, summary = diff_findings(result.findings, baseline, allow_legacy=False)
        summary["source"] = str(baseline_path)
        result = replace(result, findings=active, baseline=summary)
    return result
