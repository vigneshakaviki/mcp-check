from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from .baseline import diff_findings, load_signatures
from .capabilities import summarize_capabilities
from .models import ScanResult
from .parsers import load_config, parse_servers
from .rules import scan_server
from .suppressions import apply_suppressions, load_suppressions


def scan_file(path: Path, suppressions_path: Path | None = None, baseline_path: Path | None = None) -> ScanResult:
    config = load_config(path)
    servers = parse_servers(config)
    findings = []
    for server in servers:
        findings.extend(replace(finding, source=path.as_posix()) for finding in scan_server(server))
    active, suppressed = apply_suppressions(findings, load_suppressions(suppressions_path))
    baseline_summary = {}
    if baseline_path is not None:
        baseline = load_signatures(baseline_path)
        active, baseline_summary = diff_findings(active, baseline)
        baseline_summary["source"] = str(baseline_path)
    return ScanResult(
        source=str(path),
        findings=active,
        servers_scanned=len(servers),
        scanned_kind="MCP server",
        suppressed_findings=suppressed,
        capabilities=summarize_capabilities(servers, active),
        baseline=baseline_summary,
    )
