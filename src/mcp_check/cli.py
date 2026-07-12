from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .models import SEVERITY_ORDER
from .parsers import ConfigError
from .presets import candidate_paths, existing_preset_paths
from .reporters import to_json, to_sarif, to_terminal
from .rule_catalog import RULE_CATALOG
from .scanner import scan_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-check", description="Audit MCP server configuration without launching servers.")
    parser.add_argument("--version", action="version", version="mcp-check %s" % __version__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan an MCP configuration")
    scan.add_argument("path", type=Path, nargs="?", help="JSON, YAML, or TOML MCP configuration")
    scan.add_argument("--preset", choices=("all", "claude-desktop", "claude-code", "cursor"), help="scan existing configs from common MCP client paths")
    scan.add_argument("--suppressions", type=Path, help="JSON, YAML, or TOML suppression file")
    scan.add_argument("--baseline", type=Path, help="compare against a previous mcp-check JSON or SARIF report and only show new findings")
    scan.add_argument("--format", choices=("terminal", "json", "sarif"), default="terminal")
    scan.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    scan.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="return exit code 1 at this severity or above")

    paths = commands.add_parser("paths", help="show common MCP client config paths")
    paths.add_argument("--preset", choices=("all", "claude-desktop", "claude-code", "cursor"), default="all")
    paths.add_argument("--existing", action="store_true", help="show only paths that exist")

    rules = commands.add_parser("rules", help="list scanner rules")
    rules.add_argument("--format", choices=("terminal", "json"), default="terminal")
    return parser


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        if args.format == "json":
            print(json.dumps({"rules": RULE_CATALOG}, indent=2, sort_keys=True))
        else:
            for rule in RULE_CATALOG:
                print("%s  %-13s  %s" % (rule["id"], rule["severity"], rule["title"]))
        return

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
            results = [scan_file(path, args.suppressions, args.baseline) for path in paths]
            result = _merge_results(results)
        elif args.path:
            result = scan_file(args.path, args.suppressions, args.baseline)
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

    capabilities = {}
    baseline = {}
    for result in results:
        for key, value in result.capabilities.items():
            if isinstance(value, list):
                capabilities.setdefault(key, [])
                capabilities[key].extend(item for item in value if item not in capabilities[key])
            else:
                capabilities[key] = bool(capabilities.get(key)) or bool(value)
        if result.baseline:
            baseline.setdefault("new", 0)
            baseline.setdefault("unchanged", 0)
            baseline.setdefault("absent", 0)
            baseline["new"] += int(result.baseline.get("new", 0))
            baseline["unchanged"] += int(result.baseline.get("unchanged", 0))
            baseline["absent"] += int(result.baseline.get("absent", 0))

    return ScanResult(
        source=", ".join(result.source for result in results),
        findings=[finding for result in results for finding in result.findings],
        servers_scanned=sum(result.servers_scanned for result in results),
        suppressed_findings=[finding for result in results for finding in result.suppressed_findings],
        capabilities=capabilities,
        baseline=baseline,
    )
