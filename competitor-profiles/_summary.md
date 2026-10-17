# Market snapshot and implementation priorities

Research date: 2026-10-06. Scope: qualitative review of three directly relevant official repositories and mcp-check's current implementation. This is a competitive product assessment, not market sizing or proof of demand. No search-volume, revenue, download, or conversion data was available; none is estimated.

## Observed landscape

| Tool | Review scope | Implication for mcp-check |
| --- | --- | --- |
| [Snyk Agent Scan](snyk-agent-scan.md) | Agent discovery, MCP inspection, skills, API-backed analysis and fleet workflows | Preserve an easy no-account pre-execution entry point |
| [Cisco MCP Scanner](cisco-mcp-scanner.md) | Live MCP inspection, static exports, source/package analysis | Avoid claiming offline analysis is unique |
| [Cisco Skill Scanner](cisco-skill-scanner.md) | Skill analysis with multiple engines, recursive scanning, CI, published evaluations | Library scanning is table stakes; detection quality needs evidence |
| mcp-check | Static setup risks in configs and skill text; no server or script execution | Focus on small, deterministic pull-request checks |

These are capabilities observed in linked primary sources, not benchmark comparisons. Absence from this table does not establish that a competitor lacks a feature. Commercial pricing was not established; open-source availability does not imply every hosted capability is free.

## Recommended positioning — inference

“Review MCP configs and agent skills before they run. Offline, deterministic, and built for pull requests.”

Target developers and maintainers reviewing unfamiliar agent integrations. Lead with reviewable setup risks, minimal setup, and no target execution. Treat this as a hypothesis to validate with users. Do not claim comprehensive agent security, unique offline operation, or superior detection rates.

## Changes selected from repo inspection

1. **Skill library scanning:** a single-bundle-only workflow requires shell loops and makes aggregate CI gates cumbersome. Added `scan-skill DIR --recursive` with combined reporting, suppressions, and one baseline comparison.
2. **Source attribution:** existing skill SARIF used a bundle directory; merged config output used a comma-joined path. Findings now retain their individual file paths, with encoded SARIF URIs.
3. **Baseline identity:** identical names and evidence could collide across bundles. New reports include source-aware identities; recursive scans reject ambiguous legacy baselines.
4. **Filesystem boundaries:** reject symlinked bundle content and document discovery exclusions, skipped files, and file-level locations.
5. **Honest documentation:** narrow broad comparison language, document limits, and distinguish development features from released v0.6.0 behavior.

Existing [PR #27](https://github.com/vigneshakaviki/mcp-check/pull/27) addresses consumer Action installation; [PR #29](https://github.com/vigneshakaviki/mcp-check/pull/29) addresses project config discovery. Those changes were not duplicated. Their merge order may require reconciling CLI edits.

## Next priorities, not implemented here

- Evaluate precision and recall on a versioned labeled corpus; include benign documentation and obfuscated cases. Publish methodology before accuracy claims.
- Measure time to a first successful local scan and first CI adoption with volunteer maintainers. Do not introduce telemetry without an explicit product decision.
- Expand client formats based on actual failed setup examples rather than preset count alone.
- Consider runtime integrations only if users need them; keep them separate from the offline scan contract.

Raw README snapshots are stored locally under `raw/` and excluded from git to avoid vendoring third-party documentation. Each profile links its live primary source and records the snapshot location. No competitor code or skills were executed.
