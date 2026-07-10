from __future__ import annotations

from pathlib import Path

from .capabilities import summarize_capabilities
from .models import ScanResult
from .parsers import load_config, parse_servers
from .rules import scan_server
from .suppressions import apply_suppressions, load_suppressions


def scan_file(path: Path, suppressions_path: Path | None = None) -> ScanResult:
    config = load_config(path)
    servers = parse_servers(config)
    findings = []
    for server in servers:
        findings.extend(scan_server(server))
    active, suppressed = apply_suppressions(findings, load_suppressions(suppressions_path))
    return ScanResult(str(path), active, len(servers), suppressed, summarize_capabilities(servers, active))
