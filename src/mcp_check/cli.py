from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import SEVERITY_ORDER
from .parsers import ConfigError
from .reporters import to_json, to_sarif, to_terminal
from .scanner import scan_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-check", description="Audit MCP server configuration without launching servers.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a JSON MCP configuration")
    scan.add_argument("path", type=Path)
    scan.add_argument("--format", choices=("terminal", "json", "sarif"), default="terminal")
    scan.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    scan.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="return exit code 1 at this severity or above")
    return parser


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    try:
        result = scan_file(args.path)
    except ConfigError as exc:
        print("mcp-check: error: %s" % exc, file=sys.stderr)
        raise SystemExit(2)

    report = {"terminal": to_terminal, "json": to_json, "sarif": to_sarif}[args.format](result)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    if args.fail_on and any(SEVERITY_ORDER[item.severity] >= SEVERITY_ORDER[args.fail_on] for item in result.findings):
        raise SystemExit(1)
