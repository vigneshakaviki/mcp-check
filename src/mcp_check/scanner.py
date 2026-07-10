from __future__ import annotations

from pathlib import Path

from .models import ScanResult
from .parsers import load_config, parse_servers
from .rules import scan_server


def scan_file(path: Path) -> ScanResult:
    config = load_config(path)
    servers = parse_servers(config)
    findings = []
    for server in servers:
        findings.extend(scan_server(server))
    return ScanResult(str(path), findings, len(servers))
