from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List
from urllib.parse import urlparse

from .baseline import diff_findings, load_signatures
from .models import Finding, ScanResult
from .parsers import ConfigError
from .rules.helpers import is_placeholder, redact, unique_findings, urls_in_text
from .rules.oauth import TOKEN_QUERY
from .rules.package_provenance import _docker_image, _is_commit_pinned, _is_docker_pinned, _is_pinned
from .rules.runtime_privileges import DANGEROUS_ENV_VARS
from .rules.secrets import BEARER_VALUE, SECRET_VALUE
from .rules.ssrf import DANGEROUS_SCHEMES, LOCAL_NAMES, _is_cloud_metadata, _is_private_or_reserved
from .rules.tls_security import DISABLED_VERIFY_ENV, INSECURE_FLAGS
from .suppressions import apply_suppressions, load_suppressions


TEXT_SUFFIXES = {
    ".md", ".txt", ".sh", ".bash", ".zsh", ".fish", ".py", ".js", ".ts", ".tsx",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
}
MAX_TEXT_FILE_BYTES = 256 * 1024
SENSITIVE_PATH = re.compile(
    r"(?:\.ssh(?:/|$)|\.aws(?:/|$)|\.config/gcloud(?:/|$)|\.kube/config\b|"
    r"\.env(?:\.|$)|id_rsa\b|id_ed25519\b|credentials\.json\b)",
    re.IGNORECASE,
)
METADATA_INJECTION = re.compile(
    "|".join((
        r"(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|messages))",
        r"(do\s+not\s+(?:tell|inform|reveal|show)\s+(?:the\s+)?user)",
        r"((?:hidden|secret|invisible)\s+(?:instruction|prompt|rule))",
        r"((?:exfiltrate|steal|leak|send|upload).{0,80}(?:secret|token|credential|api[_ -]?key|\.env))",
        r"((?:system|developer)\s+prompt)",
    )),
    re.IGNORECASE | re.DOTALL,
)
HIDDEN_UNICODE = re.compile("[\u00ad\u200b\u202a-\u202e\u2060\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
URL = re.compile(r"https?://([^/\s]+)", re.IGNORECASE)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
PACKAGE_LINE = re.compile(r"\b(npx|npm|uvx|pipx|docker|podman)\b", re.IGNORECASE)
SHEBANG = re.compile(r"^#!")
FENCE = re.compile(r"^```")
RISKY_COMMAND_PATTERNS = [
    (re.compile(r"(^|\s)sudo(\s|$)", re.IGNORECASE), "privileged command", "critical"),
    (re.compile(r"rm\s+-[^\n]*r[^\n]*f|rm\s+-rf", re.IGNORECASE), "recursive force deletion", "critical"),
    (re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash|zsh|fish)\b", re.IGNORECASE), "download and execute pipeline", "critical"),
    (re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE), "dynamic command execution", "high"),
]
_ENV_INJECTION_NAMES = "|".join(re.escape(name) for name in DANGEROUS_ENV_VARS)
ENV_INJECTION_SHELL = re.compile(
    r"(?:^|[;&|]\s*)(?:export\s+|setx?\s+|\$env:)?\b(%s)\b\s*[=:]" % _ENV_INJECTION_NAMES,
    re.IGNORECASE,
)
ENV_INJECTION_CALL = re.compile(
    r"""(?:os\.environ\[|putenv\(|setenv\()\s*['"](%s)['"]""" % _ENV_INJECTION_NAMES,
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SkillBundle:
    name: str
    root: Path
    files: Dict[str, str]


def scan_skill(path: Path, suppressions_path: Path | None = None, baseline_path: Path | None = None) -> ScanResult:
    bundle = load_skill_bundle(path)
    findings = unique_findings(_scan_bundle(bundle))
    active, suppressed = apply_suppressions(findings, load_suppressions(suppressions_path))
    baseline_summary = {}
    if baseline_path is not None:
        baseline = load_signatures(baseline_path)
        active, baseline_summary = diff_findings(active, baseline)
        baseline_summary["source"] = str(baseline_path)
    return ScanResult(
        source=str(path),
        findings=active,
        servers_scanned=1,
        scanned_kind="skill bundle",
        suppressed_findings=suppressed,
        capabilities=_summarize_bundle(bundle, active),
        baseline=baseline_summary,
    )


def load_skill_bundle(path: Path) -> SkillBundle:
    if not path.exists():
        raise ConfigError("skill path does not exist: %s" % path)

    if path.is_dir():
        root = path
        skill_file = root / "SKILL.md"
    else:
        skill_file = path
        root = path.parent

    if skill_file.name != "SKILL.md":
        raise ConfigError("skill scan expects a SKILL.md file or a directory containing SKILL.md")
    if not skill_file.exists():
        raise ConfigError("skill bundle is missing SKILL.md: %s" % root)
    if skill_file.is_symlink() or not skill_file.is_file():
        raise ConfigError("skill entry must be a regular, non-symlink file: %s" % skill_file)

    files: Dict[str, str] = {}
    files["SKILL.md"] = _read_text(skill_file)

    for directory in ("scripts", "references", "assets"):
        base = root / directory
        if base.is_symlink():
            raise ConfigError("skill bundle contains a symlink: %s" % base)
        if not base.is_dir():
            continue
        for candidate in _bundle_files(base):
            if not _should_scan_file(directory, candidate):
                continue
            content = _read_optional_text(candidate)
            if content is not None:
                files[str(candidate.relative_to(root))] = content

    return SkillBundle(name=root.name, root=root, files=files)


def _walk_error(error: OSError) -> None:
    raise ConfigError("could not read skill directory: %s" % error) from error


def _bundle_files(base: Path) -> Iterable[Path]:
    for directory, dirs, files in os.walk(base, followlinks=False, onerror=_walk_error):
        dirs.sort()
        for name in sorted(dirs + files):
            candidate = Path(directory) / name
            if candidate.is_symlink():
                raise ConfigError("skill bundle contains a symlink: %s" % candidate)
            if name in files and candidate.is_file():
                yield candidate


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ConfigError("skill file is not valid UTF-8 text: %s" % path)
    except OSError as exc:
        raise ConfigError("could not read skill file %s: %s" % (path, exc)) from exc


def _read_optional_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    except OSError as exc:
        raise ConfigError("could not read skill file %s: %s" % (path, exc)) from exc


def _should_scan_file(directory: str, path: Path) -> bool:
    suffix = path.suffix.lower()
    if directory == "assets":
        return suffix in TEXT_SUFFIXES
    return suffix in TEXT_SUFFIXES or suffix == ""


def _scan_bundle(bundle: SkillBundle) -> List[Finding]:
    findings: List[Finding] = []
    for location, content in bundle.files.items():
        findings.extend(_check_metadata(bundle, location, content))
        findings.extend(_check_commands(bundle, location, content))
        findings.extend(_check_secrets(bundle, location, content))
        findings.extend(_check_sensitive_paths(bundle, location, content))
        findings.extend(_check_urls(bundle, location, content))
        findings.extend(_check_tls(bundle, location, content))
        findings.extend(_check_package_provenance(bundle, location, content))
        findings.extend(_check_env_injection(bundle, location, content))
    return findings


def _make_finding(
    bundle: SkillBundle,
    rule_id: str,
    severity: str,
    confidence: str,
    title: str,
    evidence: str,
    location: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id, severity, confidence, title, evidence, location, recommendation,
        bundle.name, source=(bundle.root / location).as_posix(),
    )


def _check_metadata(bundle: SkillBundle, location: str, content: str) -> List[Finding]:
    findings = []
    if location == "SKILL.md" or location.startswith("references/"):
        injected = METADATA_INJECTION.search(content)
        if injected:
            findings.append(_make_finding(
                bundle, "MCP007", "high", "medium",
                "Skill content contains prompt-injection language",
                _preview(injected.group(0)),
                location,
                "Review skill instructions and reference material for hidden or coercive directions before installing the bundle.",
            ))
        hidden = HIDDEN_UNICODE.search(content)
        if hidden:
            codepoint = ord(hidden.group(0))
            findings.append(_make_finding(
                bundle, "MCP007", "high", "high",
                "Skill content contains hidden Unicode controls",
                "U+%04X" % codepoint,
                location,
                "Remove invisible, bidirectional, or Unicode tag controls from skill content and inspect adjacent text for concealed instructions.",
            ))
    return findings


def _check_commands(bundle: SkillBundle, location: str, content: str) -> List[Finding]:
    for line in _lines(content):
        if SHEBANG.match(line) or FENCE.match(line):
            continue
        normalized = line.replace("`", "")
        for pattern, label, severity in RISKY_COMMAND_PATTERNS:
            if pattern.search(normalized):
                return [_make_finding(
                    bundle, "MCP001", severity, "high",
                    "Skill content contains a %s" % label,
                    _preview(line),
                    location,
                    "Review the exact instruction or script and remove privileged, destructive, or downloaded execution unless it is required and trusted.",
                )]
    return []


def _check_env_injection(bundle: SkillBundle, location: str, content: str) -> List[Finding]:
    for line in _lines(content):
        if SHEBANG.match(line) or FENCE.match(line):
            continue
        match = ENV_INJECTION_SHELL.search(line) or ENV_INJECTION_CALL.search(line)
        if match:
            name = match.group(1).upper()
            severity = DANGEROUS_ENV_VARS.get(name, "high")
            return [_make_finding(
                bundle, "MCP008", severity, "high",
                "Skill content sets a code-injection environment variable",
                _preview(line),
                location,
                "Remove %s from skill scripts unless it is required and the value is fully trusted; "
                "this variable can load attacker-controlled code into any process launched afterward." % name,
            )]
    return []


def _check_secrets(bundle: SkillBundle, location: str, content: str) -> List[Finding]:
    findings = []
    secret = SECRET_VALUE.search(content)
    if secret:
        findings.append(_make_finding(
            bundle, "MCP003", "critical", "high",
            "Credential appears directly in skill content",
            redact(secret.group(0)),
            location,
            "Replace literal credentials with environment or secret-manager references and rotate any exposed value.",
        ))
    bearer = BEARER_VALUE.search(content)
    if bearer and not is_placeholder(bearer.group(1)):
        findings.append(_make_finding(
            bundle, "MCP003", "critical", "high",
            "Bearer credential appears directly in skill content",
            "Bearer %s" % redact(bearer.group(1)),
            location,
            "Replace bearer tokens with environment-backed references and rotate the exposed token.",
        ))
    return findings


def _check_sensitive_paths(bundle: SkillBundle, location: str, content: str) -> List[Finding]:
    match = SENSITIVE_PATH.search(content)
    if not match:
        return []
    evidence = next((line for line in _lines(content) if SENSITIVE_PATH.search(line)), content.strip())
    return [_make_finding(
        bundle, "MCP002", "high", "high",
        "Skill content references a sensitive local path",
        _preview(evidence),
        location,
        "Restrict file access to the smallest project directory and never embed SSH keys, cloud credentials, or environment files in skill instructions.",
    )]


def _check_urls(bundle: SkillBundle, location: str, content: str) -> List[Finding]:
    findings = []
    for url in urls_in_text(content):
        if is_placeholder(url):
            continue
        url = url.rstrip("`")
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if scheme in {"http", "https"} and not host:
            continue
        if scheme in DANGEROUS_SCHEMES - {"file"}:
            findings.append(_make_finding(
                bundle, "MCP009", "critical", "high",
                "Skill content contains a dangerous URL scheme",
                url,
                location,
                "Reject javascript:, data:, file:, and similar URL schemes in skill instructions and references.",
            ))
            continue
        if scheme == "file":
            continue
        if _is_cloud_metadata(host):
            findings.append(_make_finding(
                bundle, "MCP009", "critical", "high",
                "Skill content references a cloud metadata endpoint",
                url,
                location,
                "Remove cloud metadata endpoints from skill instructions and block them at network policy boundaries.",
            ))
            continue
        if host in LOCAL_NAMES:
            continue
        if host in {"127.0.0.1", "::1"}:
            continue
        if _is_private_or_reserved(host):
            findings.append(_make_finding(
                bundle, "MCP009", "high", "high",
                "Skill content references a local or private network URL",
                url,
                location,
                "Avoid loopback, link-local, private, or reserved network targets in skill instructions unless the bundle is explicitly isolated for that environment.",
            ))
            continue
        if scheme == "http" and host not in LOCAL_HOSTS:
            findings.append(_make_finding(
                bundle, "MCP005", "high", "high",
                "Skill content uses an insecure remote URL",
                url,
                location,
                "Use HTTPS for remote downloads, API endpoints, and documentation links that guide executable steps.",
            ))
        elif scheme in {"http", "https"} and host not in LOCAL_HOSTS:
            findings.append(_make_finding(
                bundle, "MCP006", "medium", "medium",
                "Skill content includes remote network access",
                url,
                location,
                "Confirm the destination is required, trusted, and constrained by network policy before running the skill.",
            ))
        if TOKEN_QUERY.search(url):
            findings.append(_make_finding(
                bundle, "MCP010", "critical", "high",
                "Skill content places a token in a URL query string",
                url,
                location,
                "Never place OAuth tokens, API keys, or client secrets in URLs; use headers or secret-backed configuration instead.",
            ))
    return findings


def _check_tls(bundle: SkillBundle, location: str, content: str) -> List[Finding]:
    findings = []
    lowered = content.lower()
    for env_name, insecure_values in DISABLED_VERIFY_ENV.items():
        env_match = re.search(r"\b%s\s*=\s*([^\s`\"']+)" % re.escape(env_name), content)
        if env_match and env_match.group(1).strip().lower() in insecure_values:
            findings.append(_make_finding(
                bundle, "MCP012", "high", "high",
                "Skill content disables TLS certificate verification",
                "%s=%s" % (env_name, env_match.group(1)),
                location,
                "Enable certificate verification and remove instructions that weaken TLS checks.",
            ))
    for flag in INSECURE_FLAGS:
        if flag in lowered:
            findings.append(_make_finding(
                bundle, "MCP012", "high", "high",
                "Skill content disables TLS certificate verification",
                flag,
                location,
                "Enable certificate verification and remove instructions that weaken TLS checks.",
            ))
            break
    return findings


def _check_package_provenance(bundle: SkillBundle, location: str, content: str) -> List[Finding]:
    findings = []
    for line in _lines(content):
        if not PACKAGE_LINE.search(line):
            continue
        tokens = line.replace("`", "").strip().split()
        if not tokens:
            continue
        command = tokens[0].lower()
        if command in {"docker", "podman"}:
            image = _docker_image(tokens[1:])
            if image and not _is_docker_pinned(image):
                findings.append(_make_finding(
                    bundle, "MCP004", "high", "medium",
                    "Skill content uses a mutable container image",
                    _preview(line),
                    location,
                    "Pin container images by digest or a reviewed version tag instead of using mutable or implicit tags.",
                ))
        elif command in {"npx", "uvx", "npm", "pipx"}:
            package = _first_package_argument(command, tokens[1:])
            if not package:
                continue
            if re.search(r"(?:github\.com|git\+https?://|\.git(?:#|$))", package, re.IGNORECASE) and not _is_commit_pinned(package):
                findings.append(_make_finding(
                    bundle, "MCP004", "high", "medium",
                    "Skill content installs from a mutable Git reference",
                    _preview(line),
                    location,
                    "Pin Git-based installs to a reviewed commit SHA and verify the repository owner.",
                ))
            elif not _is_pinned(package):
                findings.append(_make_finding(
                    bundle, "MCP004", "medium", "medium",
                    "Skill content runs an unpinned package",
                    _preview(line),
                    location,
                    "Pin the package to a reviewed version and prefer a trusted registry or immutable artifact.",
                ))
    return findings


def _first_package_argument(command: str, args: List[str]) -> str | None:
    skip = {"install", "run", "x"}
    for item in args:
        if item.startswith("-") or item in skip:
            continue
        return item
    return None


def _lines(content: str) -> Iterable[str]:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped:
            yield stripped


def _preview(value: str, limit: int = 180) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _summarize_bundle(bundle: SkillBundle, findings: List[Finding]) -> Dict[str, object]:
    urls = sorted({
        url
        for content in bundle.files.values()
        for url in urls_in_text(content)
        if not is_placeholder(url)
    })
    return {
        "shell": any(item.rule_id == "MCP001" for item in findings),
        "filesystem": sorted({item.evidence for item in findings if item.rule_id == "MCP002"}),
        "secrets": sorted({"%s.%s" % (item.server, item.location) for item in findings if item.rule_id == "MCP003"}),
        "network": urls,
        "packages": sorted({item.evidence for item in findings if item.rule_id == "MCP004"}),
        "oauth": any(item.rule_id == "MCP010" for item in findings),
        "metadata_injection": any(item.rule_id == "MCP007" for item in findings),
        "ssrf": any(item.rule_id == "MCP009" for item in findings),
        "tls_verification_disabled": any(item.rule_id == "MCP012" for item in findings),
    }
