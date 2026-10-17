from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .aggregation import merge_results as _merge_results
from .baseline import diff_findings, load_signatures
from .models import SEVERITY_ORDER
from .parsers import ConfigError
from .presets import candidate_paths, existing_preset_paths
from .reporters import to_json, to_sarif, to_terminal
from .rule_catalog import RULE_CATALOG
from .scanner import scan_file
from .skill_library import scan_skill_library
from .skill_scanner import scan_skill


def build_parser() -> argparse.ArgumentParser:
    preset_choices = ("all", "claude-desktop", "claude-code", "copilot-cli", "codex", "cursor")
    parser = argparse.ArgumentParser(prog="mcp-check", description="Audit MCP server configuration without launching servers.")
    parser.add_argument("--version", action="version", version="mcp-check %s" % __version__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan an MCP configuration")
    scan.add_argument("path", type=Path, nargs="?", help="JSON, YAML, or TOML MCP configuration")
    scan.add_argument("--preset", choices=preset_choices, help="scan existing configs from common MCP client paths")
    scan.add_argument("--suppressions", type=Path, help="JSON, YAML, or TOML suppression file")
    scan.add_argument("--baseline", type=Path, help="compare against a previous mcp-check JSON or SARIF report and only show new findings")
    scan.add_argument("--format", choices=("terminal", "json", "sarif"), default="terminal")
    scan.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    scan.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="return exit code 1 at this severity or above")

    scan_skill_cmd = commands.add_parser("scan-skill", help="scan a skill bundle without executing it")
    scan_skill_cmd.add_argument("path", type=Path, help="SKILL.md file or directory containing SKILL.md")
    scan_skill_cmd.add_argument("--recursive", action="store_true", help="scan every SKILL.md bundle under a directory")
    scan_skill_cmd.add_argument("--suppressions", type=Path, help="JSON, YAML, or TOML suppression file")
    scan_skill_cmd.add_argument("--baseline", type=Path, help="compare against a previous mcp-check JSON or SARIF report and only show new findings")
    scan_skill_cmd.add_argument("--format", choices=("terminal", "json", "sarif"), default="terminal")
    scan_skill_cmd.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    scan_skill_cmd.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="return exit code 1 at this severity or above")

    paths = commands.add_parser("paths", help="show common MCP client config paths")
    paths.add_argument("--preset", choices=preset_choices, default="all")
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
        if args.command == "scan-skill":
            scanner = scan_skill_library if args.recursive else scan_skill
            result = scanner(args.path, args.suppressions, args.baseline)
        else:
            if args.preset:
                paths = existing_preset_paths(args.preset)
                if not paths:
                    print("mcp-check: error: no existing config paths found for preset %r" % args.preset, file=sys.stderr)
                    raise SystemExit(2)
                # Apply baseline after merging. Applying it per file counts the
                # same baseline findings as absent once for every preset path.
                results = [scan_file(path, args.suppressions) for path in paths]
                result = _merge_results(results)
                if args.baseline:
                    active, summary = diff_findings(result.findings, load_signatures(args.baseline))
                    summary["source"] = str(args.baseline)
                    result = replace(result, findings=active, baseline=summary)
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
