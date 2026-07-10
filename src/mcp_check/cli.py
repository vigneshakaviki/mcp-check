from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import SEVERITY_ORDER
from .parsers import ConfigError
from .presets import candidate_paths, existing_preset_paths
from .reporters import to_json, to_sarif, to_terminal
from .scanner import scan_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-check", description="Audit MCP server configuration without launching servers.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan an MCP configuration")
    scan.add_argument("path", type=Path, nargs="?", help="JSON, YAML, or TOML MCP configuration")
    scan.add_argument("--preset", choices=("all", "claude-desktop", "claude-code", "cursor"), help="scan existing configs from common MCP client paths")
    scan.add_argument("--suppressions", type=Path, help="JSON, YAML, or TOML suppression file")
    scan.add_argument("--format", choices=("terminal", "json", "sarif"), default="terminal")
    scan.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    scan.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="return exit code 1 at this severity or above")

    paths = commands.add_parser("paths", help="show common MCP client config paths")
    paths.add_argument("--preset", choices=("all", "claude-desktop", "claude-code", "cursor"), default="all")
    paths.add_argument("--existing", action="store_true", help="show only paths that exist")
    return parser


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "paths":
        paths = existing_preset_paths(args.preset) if args.existing else candidate_paths()[args.preset]
        for path in paths:
            print(path)
        return

    try:
        if args.preset:
            paths = existing_preset_paths(args.preset)
            if not paths:
                print("mcp-check: error: no existing config paths found for preset %r" % args.preset, file=sys.stderr)
                raise SystemExit(2)
            results = [scan_file(path, args.suppressions) for path in paths]
            result = _merge_results(results)
        elif args.path:
            result = scan_file(args.path, args.suppressions)
        else:
            print("mcp-check: error: scan requires a path or --preset", file=sys.stderr)
            raise SystemExit(2)
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


def _merge_results(results):
    from .models import ScanResult

    return ScanResult(
        source=", ".join(result.source for result in results),
        findings=[finding for result in results for finding in result.findings],
        servers_scanned=sum(result.servers_scanned for result in results),
        suppressed_findings=[finding for result in results for finding in result.suppressed_findings],
    )
