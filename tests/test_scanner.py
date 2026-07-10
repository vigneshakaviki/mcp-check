import json
from pathlib import Path

import pytest

from mcp_check.parsers import ConfigError, load_config, parse_servers
from mcp_check.reporters import to_sarif
from mcp_check.scanner import scan_file


ROOT = Path(__file__).parent


def test_safe_fixture_has_no_findings():
    result = scan_file(ROOT / "fixtures" / "safe.json")
    assert result.servers_scanned == 1
    assert result.findings == []


def test_mixed_fixture_detects_risks_and_redacts_secret():
    result = scan_file(ROOT / "fixtures" / "mixed.json")
    rule_ids = {finding.rule_id for finding in result.findings}
    assert {"MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "MCP007", "MCP008"}.issubset(rule_ids)
    assert all("sk-12345678901234567890" not in finding.evidence for finding in result.findings)


def test_sarif_is_valid_enough_for_ci():
    payload = json.loads(to_sarif(scan_file(ROOT / "fixtures" / "mixed.json")))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "mcp-check"
    assert payload["runs"][0]["results"]


def test_invalid_config_is_reported(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ConfigError, match="root must be a JSON object"):
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
