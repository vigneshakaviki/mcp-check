# Scan agent skill libraries

Recursive scanning is available in the development checkout and is not part of the published v0.6.0 release. Install from a reviewed checkout with `python -m pip install .`.

## Single bundle or entire library

```bash
mcp-check scan-skill ./skills/deploy
mcp-check scan-skill ./skills/deploy/SKILL.md
mcp-check scan-skill ./skills --recursive --fail-on high
mcp-check scan-skill ./.agents/skills --recursive --format json --output skills.json
mcp-check scan-skill ./skills --recursive --format sarif --output skills.sarif --fail-on high
```

`--recursive` requires a directory. It finds every regular `SKILL.md` beneath it, including one at the root, in stable path order. Hidden agent directories such as `.agents` and `.claude` are included.

Discovery skips `.git`, `.hg`, `.svn`, `.venv`, `venv`, `node_modules`, `__pycache__`, and symlinked directories. Inside a discovered bundle, symlinked `SKILL.md`, `scripts/`, `references/`, `assets/`, or content beneath those directories causes an error. This avoids reading linked content outside the reviewed bundle. Explicitly selected root directories are treated as the scan boundary; this is not an operating-system sandbox or protection against concurrent filesystem mutation.

Each bundle scans `SKILL.md` and supported text files in `scripts/`, `references/`, and `assets/`. Optional files larger than 256 KiB, invalid UTF-8 optional files, and unsupported binary formats are skipped. Other top-level files are not inspected. A malformed entry file or unreadable directory aborts the scan. No bundles found is an error, not a successful empty scan.

No target code executes and no endpoint is contacted. Pattern-based analysis can miss obfuscated or context-dependent attacks and can flag legitimate privileged operations. Review findings alongside the bundle's purpose and code.

## Reports and CI exit codes

One report aggregates all discovered bundles and capabilities. `servers_scanned` remains the count field for compatibility; `scanned_kind` is `skill bundle`. Findings and suppressed findings include a `source` file path. Duplicate bundle names retain distinct paths.

SARIF links to the file containing the finding, including scripts and references. The current region is file-level (`startLine: 1`), not an exact matched line. Paths containing spaces or `#` are URI-encoded.

| Exit | Meaning |
| --- | --- |
| `0` | Scan completed; no active finding met `--fail-on`, or no threshold was set |
| `1` | Scan completed; at least one active finding met the threshold |
| `2` | Invalid input, discovery failure, or scan error |

Reports are written before threshold exit `1`. Scan errors abort without producing a new report; an existing output file is not removed. CI should only upload output from a completed scan. The composite Action's `paths` input still scans MCP configurations; use the CLI directly for skill libraries.

## File-aware baselines

```bash
# Review this report before accepting it as a baseline.
mcp-check scan-skill ./skills --recursive --format json --output accepted-skills.json

# Later runs fail only for new high/critical findings.
mcp-check scan-skill ./skills --recursive --baseline accepted-skills.json --fail-on high
```

JSON and SARIF baselines are supported. New signatures include the source path as well as the rule, bundle name, logical location, title, and evidence. An identical finding in another bundle is new. Counts of new, unchanged, and absent findings are computed once across the full library.

Keep invocation paths consistent between baseline and subsequent scans; prefer paths relative to the repository root for CI portability. Renamed or relocated files are intentionally treated as new. Older reports without per-finding source identities remain supported for single-bundle scans. Recursive scans reject non-empty legacy baselines with instructions to regenerate them, because they cannot safely distinguish duplicate names.

`--suppressions` uses the existing rule/server/location policy and keeps suppressed findings visible. Policies match bundle names, so a suppression for `deploy` applies to every bundle named `deploy` in the scanned library. Review broad suppressions carefully.
