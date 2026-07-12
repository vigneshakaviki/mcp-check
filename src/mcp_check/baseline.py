from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Set, Tuple

from .models import Finding
from .parsers import ConfigError


Signature = Tuple[str, str, str, str, str]


def load_signatures(path: Path | None) -> Set[Signature]:
    if path is None:
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError("could not read baseline file %s: %s" % (path, exc)) from exc
    except json.JSONDecodeError as exc:
        raise ConfigError("invalid JSON in baseline file %s at line %d column %d: %s" % (path, exc.lineno, exc.colno, exc.msg)) from exc
    if not isinstance(payload, dict):
        raise ConfigError("baseline file must contain a JSON object")
    if "findings" in payload:
        return {_finding_signature(item) for item in _iter_dicts(payload.get("findings", []))}
    if payload.get("version") == "2.1.0" and "runs" in payload:
        signatures = set()
        for run in payload.get("runs", []):
            if not isinstance(run, dict):
                continue
            signatures.update(_sarif_signature(item) for item in _iter_dicts(run.get("results", [])))
        return signatures
    raise ConfigError("baseline file must be mcp-check JSON or SARIF 2.1.0 output")


def diff_findings(findings: Iterable[Finding], baseline: Set[Signature]) -> tuple[list[Finding], Dict[str, int]]:
    active = []
    unchanged = 0
    for finding in findings:
        if finding.signature() in baseline:
            unchanged += 1
            continue
        active.append(finding)
    baseline_only = max(len(baseline) - unchanged, 0)
    summary = {
        "new": len(active),
        "unchanged": unchanged,
        "absent": baseline_only,
    }
    return active, summary


def _iter_dicts(items: Iterable[Any]) -> Iterable[Dict[str, Any]]:
    for item in items:
        if isinstance(item, dict):
            yield item


def _finding_signature(item: Dict[str, Any]) -> Signature:
    return (
        str(item.get("rule_id", "")),
        str(item.get("server", "")),
        str(item.get("location", "")),
        str(item.get("title", "")),
        str(item.get("evidence", "")),
    )


def _sarif_signature(item: Dict[str, Any]) -> Signature:
    location = ""
    server = ""
    locations = item.get("locations") or []
    if locations and isinstance(locations[0], dict):
        logical = locations[0].get("logicalLocations") or []
        if logical and isinstance(logical[0], dict):
            name = str(logical[0].get("name", ""))
            if "." in name:
                server, location = name.split(".", 1)
            else:
                server = name
    message = item.get("message") or {}
    text = str(message.get("text", ""))
    title, evidence = _split_message(text)
    return (
        str(item.get("ruleId", "")),
        server,
        location,
        title,
        evidence,
    )


def _split_message(text: str) -> tuple[str, str]:
    if ": " not in text:
        return text, ""
    title, evidence = text.split(": ", 1)
    return title, evidence
