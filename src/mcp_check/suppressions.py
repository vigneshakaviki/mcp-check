from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .models import Finding
from .parsers import ConfigError, load_config


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    server: str
    location: str
    reason: str

    def matches(self, finding: Finding) -> bool:
        return (
            _match(self.rule_id, finding.rule_id)
            and _match(self.server, finding.server)
            and _match(self.location, finding.location)
        )


def _match(pattern: str, value: str) -> bool:
    return pattern in {"*", value}


def load_suppressions(path: Path | None) -> List[Suppression]:
    if path is None:
        return []
    config = load_config(path)
    raw = config.get("suppressions", [])
    if not isinstance(raw, list):
        raise ConfigError("'suppressions' must be a list")

    suppressions = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError("suppression %d must be an object" % index)
        suppressions.append(Suppression(
            rule_id=_field(item, "rule_id", index),
            server=_field(item, "server", index, default="*"),
            location=_field(item, "location", index, default="*"),
            reason=_field(item, "reason", index, default="suppressed by policy"),
        ))
    return suppressions


def apply_suppressions(findings: Iterable[Finding], suppressions: Iterable[Suppression]) -> Tuple[List[Finding], List[Finding]]:
    active = []
    suppressed = []
    rules = list(suppressions)
    for finding in findings:
        match = next((rule for rule in rules if rule.matches(finding)), None)
        if match is None:
            active.append(finding)
        else:
            suppressed.append(finding.suppressed(match.reason))
    return active, suppressed


def _field(item: Dict[str, Any], key: str, index: int, default: str | None = None) -> str:
    value = item.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("suppression %d must contain a non-empty %r field" % (index, key))
    return value
