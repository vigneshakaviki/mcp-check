import json
from pathlib import Path

import pytest

from mcp_check.cli import main
from mcp_check.parsers import ConfigError, load_config, parse_servers
from mcp_check.reporters import to_sarif
from mcp_check.scanner import scan_file


ROOT = Path(__file__).parent


def test_safe_fixture_has_no_findings():
    result = scan_file(ROOT / "fixtures" / "safe.json")
    assert result.servers_scanned == 1
    assert result.findings == []


def test_yaml_and_toml_fixtures_are_supported():
    assert scan_file(ROOT / "fixtures" / "safe.yaml").findings == []
    assert scan_file(ROOT / "fixtures" / "safe.toml").findings == []


def test_current_client_config_shapes_are_supported():
    vscode = scan_file(ROOT / "fixtures" / "safe-vscode.json")
    codex = scan_file(ROOT / "fixtures" / "safe-codex.toml")

    assert vscode.servers_scanned == 1
    assert vscode.findings == []
    assert vscode.capabilities["network"] == ["https://mcp.example.test/mcp"]
    assert codex.servers_scanned == 1
    assert codex.findings == []
    assert codex.capabilities["network"] == ["https://mcp.example.test/mcp"]


@pytest.mark.parametrize("url_field", ["uri", "httpUrl", "serverUrl"])
def test_remote_url_field_aliases_are_supported(tmp_path, url_field):
    path = tmp_path / (url_field + ".json")
    path.write_text(json.dumps({
        "mcpServers": {
            "remote": {url_field: "https://mcp.example.test/mcp"},
        },
    }), encoding="utf-8")

    result = scan_file(path)
    assert result.findings == []
    assert result.capabilities["network"] == ["https://mcp.example.test/mcp"]


def test_mixed_fixture_detects_risks_and_redacts_secret():
    result = scan_file(ROOT / "fixtures" / "mixed.json")
    rule_ids = {finding.rule_id for finding in result.findings}
    assert {"MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "MCP007", "MCP008"}.issubset(rule_ids)
    assert all("sk-12345678901234567890" not in finding.evidence for finding in result.findings)
    assert result.capabilities["shell"] is True
    assert result.capabilities["docker"] is True
    assert result.capabilities["network"]


def test_private_network_and_dangerous_urls_are_detected():
    result = scan_file(ROOT.parent / "examples" / "unsafe" / "private-network-url.json")
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "MCP009" in rule_ids
    assert any("169.254.169.254" in finding.evidence for finding in result.findings)
    assert result.capabilities["ssrf"] is True


def test_oauth_misconfigurations_are_detected():
    result = scan_file(ROOT.parent / "examples" / "unsafe" / "oauth-broad-scope.json")
    titles = {finding.title for finding in result.findings}
    assert "MCP configuration requests broad OAuth scopes" in titles
    assert "OAuth URL does not use HTTPS" in titles
    assert "OAuth or bearer credential appears directly in MCP configuration" in titles
    assert result.capabilities["oauth"] is True


def test_local_http_transport_is_not_ssrf_but_is_warned():
    result = scan_file(ROOT.parent / "examples" / "unsafe" / "local-http-transport.json")
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "MCP011" in rule_ids
    assert "MCP009" not in rule_ids


def test_wildcard_bind_is_detected():
    result = scan_file(ROOT.parent / "examples" / "unsafe" / "wildcard-bind.json")
    assert any(finding.rule_id == "MCP011" for finding in result.findings)


def test_oauth_token_query_and_missing_pkce_s256_are_detected():
    result = scan_file(ROOT.parent / "examples" / "unsafe" / "oauth-token-query.json")
    titles = {finding.title for finding in result.findings}
    assert "OAuth token appears in a URL query string" in titles
    assert "OAuth metadata does not advertise PKCE S256 support" in titles


def test_nested_header_and_argument_credentials_are_redacted(tmp_path):
    path = tmp_path / "credentials.json"
    literal_token = "literal-secret-token-1234567890"
    path.write_text(json.dumps({
        "mcpServers": {
            "remote": {
                "url": "https://user:password@example.test/mcp",
                "headers": {"Authorization": "Bearer %s" % literal_token},
            },
            "local": {
                "command": "uvx",
                "args": ["trusted-server==1.2.3", "--api-key", literal_token],
            },
        },
    }), encoding="utf-8")

    result = scan_file(path)
    secret_findings = [finding for finding in result.findings if finding.rule_id == "MCP003"]
    assert len(secret_findings) == 3
    assert all(literal_token not in finding.evidence for finding in secret_findings)
    assert all("password" not in finding.evidence for finding in secret_findings)


def test_header_secret_references_are_not_reported(tmp_path):
    path = tmp_path / "references.json"
    path.write_text(json.dumps({
        "mcpServers": {
            "remote": {
                "url": "https://example.test/mcp",
                "headers": {
                    "Authorization": "Bearer ${MCP_TOKEN}",
                    "X-API-Key": "YOUR_API_KEY",
                },
            },
        },
    }), encoding="utf-8")

    assert scan_file(path).findings == []


def test_disabled_tls_verification_is_detected(tmp_path):
    path = tmp_path / "tls.json"
    path.write_text(json.dumps({
        "mcpServers": {
            "env-disable": {
                "command": "node",
                "args": ["server.js"],
                "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
            },
            "flag-disable": {
                "command": "uvx",
                "args": ["trusted-server==1.2.3", "--skip-tls-verify"],
            },
            "setting-disable": {
                "url": "https://example.test/mcp",
                "tls": {"rejectUnauthorized": False},
            },
        },
    }), encoding="utf-8")

    result = scan_file(path)
    tls_findings = [finding for finding in result.findings if finding.rule_id == "MCP012"]
    assert len(tls_findings) == 3
    assert result.capabilities["tls_verification_disabled"] is True


def test_enabled_tls_verification_is_not_reported(tmp_path):
    path = tmp_path / "tls-safe.json"
    path.write_text(json.dumps({
        "mcpServers": {
            "remote": {
                "url": "https://example.test/mcp",
                "tls": {"rejectUnauthorized": True, "verifySsl": True},
            },
        },
    }), encoding="utf-8")

    assert scan_file(path).findings == []


def test_wildcard_origin_is_detected():
    result = scan_file(ROOT.parent / "examples" / "unsafe" / "wildcard-origin.json")
    assert any(
        finding.rule_id == "MCP011" and finding.title == "MCP server allows requests from any web origin"
        for finding in result.findings
    )


def test_hidden_unicode_in_metadata_is_detected_without_echoing_it():
    result = scan_file(ROOT.parent / "examples" / "unsafe" / "hidden-unicode-description.json")
    finding = next(item for item in result.findings if item.title == "MCP metadata contains hidden Unicode controls")
    assert finding.rule_id == "MCP007"
    assert finding.evidence == "U+202E RIGHT-TO-LEFT OVERRIDE"


def test_named_and_wildcard_tool_auto_approval_are_detected(tmp_path):
    path = tmp_path / "approvals.json"
    path.write_text(json.dumps({
        "mcpServers": {
            "named": {
                "command": "uvx",
                "args": ["trusted-server==1.2.3"],
                "alwaysAllow": ["read_file"],
            },
            "wildcard": {
                "url": "https://example.test/mcp",
                "autoApprove": ["*"],
            },
            "manual": {
                "url": "https://safe.example.test/mcp",
                "alwaysAllow": [],
                "autoApprove": {"read_file": False},
            },
        },
    }), encoding="utf-8")

    approvals = [item for item in scan_file(path).findings if item.rule_id == "MCP013"]
    assert [(item.server, item.severity) for item in approvals] == [("named", "medium"), ("wildcard", "high")]


def test_additional_broad_oauth_scopes_are_detected(tmp_path):
    path = tmp_path / "scopes.json"
    path.write_text(json.dumps({
        "mcpServers": {
            "oauth": {
                "url": "https://example.test/mcp",
                "oauth": {"scopes": ["all", "full-access", "db:*"]},
            },
        },
    }), encoding="utf-8")

    findings = [
        item
        for item in scan_file(path).findings
        if item.title == "MCP configuration requests broad OAuth scopes"
    ]
    assert len(findings) == 3


def test_sarif_is_valid_enough_for_ci():
    payload = json.loads(to_sarif(scan_file(ROOT / "fixtures" / "mixed.json")))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "mcp-check"
    assert payload["runs"][0]["results"]


def test_suppressions_keep_findings_visible(tmp_path):
    suppressions = tmp_path / "suppressions.json"
    suppressions.write_text(json.dumps({
        "suppressions": [{
            "rule_id": "MCP004",
            "server": "unsafe-tools",
            "location": "args",
            "reason": "accepted for test",
        }],
    }), encoding="utf-8")

    result = scan_file(ROOT / "fixtures" / "mixed.json", suppressions)
    assert not any(finding.rule_id == "MCP004" and finding.server == "unsafe-tools" for finding in result.findings)
    assert any(finding.rule_id == "MCP004" and finding.suppression_reason == "accepted for test" for finding in result.suppressed_findings)

    payload = json.loads(to_sarif(result))
    assert any("suppressions" in item for item in payload["runs"][0]["results"])


def test_baseline_filters_known_findings_as_json(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(scan_file(ROOT / "fixtures" / "mixed.json").as_dict()), encoding="utf-8")

    result = scan_file(ROOT / "fixtures" / "mixed.json", baseline_path=baseline)
    assert result.findings == []
    assert result.baseline["new"] == 0
    assert result.baseline["unchanged"] > 0


def test_baseline_filters_known_findings_as_sarif(tmp_path):
    baseline = tmp_path / "baseline.sarif"
    baseline.write_text(to_sarif(scan_file(ROOT / "fixtures" / "mixed.json")), encoding="utf-8")

    result = scan_file(ROOT / "fixtures" / "mixed.json", baseline_path=baseline)
    assert result.findings == []
    assert result.baseline["new"] == 0
    assert result.baseline["unchanged"] > 0


def test_invalid_config_is_reported(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ConfigError, match="root must be a JSON/YAML/TOML object"):
        load_config(path)


def test_missing_servers_is_reported():
    with pytest.raises(ConfigError, match="mcpServers"):
        parse_servers({})


def test_placeholder_credentials_are_not_reported(tmp_path):
    path = tmp_path / "placeholder.json"
    path.write_text(json.dumps({
        "mcpServers": {
            "template": {
                "command": "node",
                "args": ["server.js"],
                "env": {
                    "SUPABASE_URL": "https://YOUR_PROJECT_REF.supabase.co",
                    "SUPABASE_SERVICE_ROLE_KEY": "YOUR_SUPABASE_SERVICE_ROLE_KEY",
                    "MCP_API_KEY": "PASTE_YOUR_KEY_FROM_SETTINGS",
                },
            },
        },
    }), encoding="utf-8")

    result = scan_file(path)
    assert result.findings == []


def test_rules_command_lists_catalog(capsys):
    main(["rules"])
    output = capsys.readouterr().out
    assert "MCP001" in output
    assert "MCP011" in output
    assert "MCP012" in output
    assert "MCP013" in output


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "mcp-check" in capsys.readouterr().out
