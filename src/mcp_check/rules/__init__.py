from __future__ import annotations

from typing import Callable, List

from ..models import Finding, ServerConfig
from .command_execution import check_command_execution
from .metadata_injection import check_metadata_injection
from .network_access import check_network_access
from .package_provenance import check_package_provenance
from .runtime_privileges import check_runtime_privileges
from .secrets import check_secrets
from .sensitive_paths import check_sensitive_paths


Rule = Callable[[ServerConfig], List[Finding]]
RULES: List[Rule] = [
    check_command_execution,
    check_sensitive_paths,
    check_secrets,
    check_package_provenance,
    check_network_access,
    check_metadata_injection,
    check_runtime_privileges,
]


def scan_server(server: ServerConfig) -> List[Finding]:
    findings = []
    for rule in RULES:
        findings.extend(rule(server))
    return sorted(findings, key=lambda item: (item.server, item.rule_id, item.location))
