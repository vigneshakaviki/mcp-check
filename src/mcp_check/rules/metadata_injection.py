from __future__ import annotations

import re

from ..models import ServerConfig
from .helpers import all_text_parts, make_finding, unique_findings


METADATA_KEYS = re.compile(r"(?:description|instruction|prompt|tool|resource|schema|annotation)", re.IGNORECASE)
INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|messages)",
    r"do\s+not\s+(?:tell|inform|reveal|show)\s+(?:the\s+)?user",
    r"(?:hidden|secret|invisible)\s+(?:instruction|prompt|rule)",
    r"(?:exfiltrate|steal|leak|send|upload).{0,80}(?:secret|token|credential|api[_ -]?key|\.env)",
    r"(?:system|developer)\s+prompt",
]
INJECTION = re.compile("|".join("(%s)" % pattern for pattern in INJECTION_PATTERNS), re.IGNORECASE | re.DOTALL)


def check_metadata_injection(server: ServerConfig):
    findings = []
    for location, value in all_text_parts(server):
        if not METADATA_KEYS.search(location):
            continue
        if INJECTION.search(value):
            findings.append(make_finding(
                server, "MCP007", "high", "medium",
                "MCP metadata contains prompt-injection language",
                value[:180],
                location,
                "Review tool descriptions, prompts, and annotations for hidden instructions before approving the server.",
            ))
    return unique_findings(findings)
