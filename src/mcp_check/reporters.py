from __future__ import annotations

import json
from typing import Any, Dict

from .models import Finding, ScanResult, SEVERITY_ORDER


def to_json(result: ScanResult) -> str:
    return json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n"


def to_terminal(result: ScanResult) -> str:
    lines = [
        "mcp-check: %s" % result.source,
        "Scanned %d MCP server(s); %d finding(s)." % (result.servers_scanned, len(result.findings)),
    ]
    if result.suppressed_findings:
        lines.append("Suppressed %d finding(s)." % len(result.suppressed_findings))
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    for finding in result.findings:
        lines.extend([
            "",
            "[%s] %s (%s confidence)" % (finding.severity.upper(), finding.title, finding.confidence),
            "  %s %s" % (finding.rule_id, finding.location),
            "  Evidence: %s" % finding.evidence,
            "  Fix: %s" % finding.recommendation,
        ])
    return "\n".join(lines) + "\n"


def _level(severity: str) -> str:
    return "error" if SEVERITY_ORDER[severity] >= SEVERITY_ORDER["high"] else "warning"


def to_sarif(result: ScanResult) -> str:
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for finding in result.findings:
        rules.setdefault(finding.rule_id, {"id": finding.rule_id, "name": finding.title, "help": {"text": finding.recommendation}})
        results.append(_sarif_result(result, finding))
    for finding in result.suppressed_findings:
        rules.setdefault(finding.rule_id, {"id": finding.rule_id, "name": finding.title, "help": {"text": finding.recommendation}})
        suppressed = _sarif_result(result, finding)
        suppressed["suppressions"] = [{
            "kind": "external",
            "justification": finding.suppression_reason or "suppressed by policy",
        }]
        suppressed["properties"]["suppressed"] = True
        results.append(suppressed)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "mcp-check", "version": "0.2.0", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _sarif_result(result: ScanResult, finding: Finding) -> Dict[str, Any]:
    return {
            "ruleId": finding.rule_id,
            "level": _level(finding.severity),
            "message": {"text": "%s: %s" % (finding.title, finding.evidence)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": result.source},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": "%s.%s" % (finding.server, finding.location)}],
            }],
            "properties": {"severity": finding.severity, "confidence": finding.confidence},
        }
