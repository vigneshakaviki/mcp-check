from __future__ import annotations

from .models import ScanResult


def merge_results(results: list[ScanResult]) -> ScanResult:
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
        scanned_kind=results[0].scanned_kind if results else "MCP server",
        suppressed_findings=[finding for result in results for finding in result.suppressed_findings],
        capabilities=capabilities,
        baseline=baseline,
    )
