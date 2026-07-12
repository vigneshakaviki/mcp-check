from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Dict, List, Optional

from . import __version__


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class ServerConfig:
    name: str
    data: Dict[str, Any]

    @property
    def command(self) -> str:
        return str(self.data.get("command", ""))

    @property
    def args(self) -> List[str]:
        value = self.data.get("args", [])
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)] if value else []

    @property
    def env(self) -> Dict[str, Any]:
        value = self.data.get("env", {})
        return value if isinstance(value, dict) else {}

    @property
    def url(self) -> str:
        return str(self.data.get("url", ""))


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    confidence: str
    title: str
    evidence: str
    location: str
    recommendation: str
    server: str
    suppression_reason: Optional[str] = None

    def signature(self) -> tuple[str, str, str, str, str]:
        return (self.rule_id, self.server, self.location, self.title, self.evidence)

    def as_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        if value["suppression_reason"] is None:
            del value["suppression_reason"]
        return value

    def suppressed(self, reason: str) -> "Finding":
        return replace(self, suppression_reason=reason)


@dataclass(frozen=True)
class ScanResult:
    source: str
    findings: List[Finding]
    servers_scanned: int
    suppressed_findings: Optional[List[Finding]] = None
    capabilities: Optional[Dict[str, Any]] = None
    baseline: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        if self.suppressed_findings is None:
            object.__setattr__(self, "suppressed_findings", [])
        if self.capabilities is None:
            object.__setattr__(self, "capabilities", {})
        if self.baseline is None:
            object.__setattr__(self, "baseline", {})

    def highest_severity(self) -> str:
        if not self.findings:
            return "none"
        return max(self.findings, key=lambda item: SEVERITY_ORDER[item.severity]).severity

    def as_dict(self) -> Dict[str, Any]:
        value = {
            "tool": {"name": "mcp-check", "version": __version__},
            "source": self.source,
            "servers_scanned": self.servers_scanned,
            "finding_count": len(self.findings),
            "suppressed_finding_count": len(self.suppressed_findings),
            "highest_severity": self.highest_severity(),
            "capabilities": self.capabilities,
            "findings": [finding.as_dict() for finding in self.findings],
            "suppressed_findings": [finding.as_dict() for finding in self.suppressed_findings],
        }
        if self.baseline:
            value["baseline"] = self.baseline
        return value
