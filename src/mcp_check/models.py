from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List


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

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    source: str
    findings: List[Finding]
    servers_scanned: int

    def highest_severity(self) -> str:
        if not self.findings:
            return "none"
        return max(self.findings, key=lambda item: SEVERITY_ORDER[item.severity]).severity

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tool": {"name": "mcp-check", "version": "0.1.0"},
            "source": self.source,
            "servers_scanned": self.servers_scanned,
            "finding_count": len(self.findings),
            "highest_severity": self.highest_severity(),
            "findings": [finding.as_dict() for finding in self.findings],
        }
