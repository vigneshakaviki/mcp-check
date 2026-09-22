import json

import pytest

from mcp_check.cli import main
from mcp_check.presets import project_paths


def write_config(root, relative, name, unsafe=False):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    key = "servers" if relative.startswith(".vscode/") else "mcpServers"
    server = {"url": "https://mcp.example.test/mcp"}
    if unsafe:
        server["autoApprove"] = ["*"]
    path.write_text(json.dumps({key: {name: server}}), encoding="utf-8")
    return path


def test_project_scans_all_known_paths_without_recursing(tmp_path, capsys):
    expected = [
        write_config(tmp_path, ".mcp.json", "claude"),
        write_config(tmp_path, ".cursor/mcp.json", "cursor"),
        write_config(tmp_path, ".vscode/mcp.json", "vscode"),
    ]
    write_config(tmp_path, "nested/.mcp.json", "ignored", unsafe=True)
    assert project_paths(tmp_path) == expected
    main(["scan", "--project", str(tmp_path), "--format", "json", "--fail-on", "low"])
    report = json.loads(capsys.readouterr().out)
    assert report["servers_scanned"] == 3
    assert report["findings"] == []
    assert all(str(path) in report["source"] for path in expected)
    assert report["capabilities"]["network"] == ["https://mcp.example.test/mcp"]


@pytest.mark.parametrize("format", ["json", "sarif"])
def test_project_threshold_and_report_output(tmp_path, format):
    write_config(tmp_path, ".mcp.json", "unsafe", unsafe=True)
    output = tmp_path / "report.json"
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--project", str(tmp_path), "--format", format,
              "--output", str(output), "--fail-on", "high"])
    assert exc.value.code == 1
    report = json.loads(output.read_text())
    if format == "json":
        assert report["findings"][0]["rule_id"] == "MCP013"
    else:
        assert report["runs"][0]["results"][0]["ruleId"] == "MCP013"


def test_project_baseline_applied_to_combined_report(tmp_path, capsys):
    write_config(tmp_path, ".mcp.json", "claude", unsafe=True)
    write_config(tmp_path, ".cursor/mcp.json", "cursor", unsafe=True)
    baseline = tmp_path / "baseline.json"
    main(["scan", "--project", str(tmp_path), "--format", "json", "--output", str(baseline)])
    main(["scan", "--project", str(tmp_path), "--format", "json",
          "--baseline", str(baseline), "--fail-on", "low"])
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == []
    assert report["baseline"] == {"new": 0, "unchanged": 2, "absent": 0, "source": str(baseline)}


def test_project_suppressions(tmp_path, capsys):
    write_config(tmp_path, ".mcp.json", "unsafe", unsafe=True)
    suppressions = tmp_path / "suppressions.json"
    suppressions.write_text(json.dumps({"suppressions": [{
        "rule_id": "MCP013", "server": "unsafe", "location": "*", "reason": "Reviewed"
    }]}))
    main(["scan", "--project", str(tmp_path), "--format", "json",
          "--suppressions", str(suppressions), "--fail-on", "low"])
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == []
    assert report["suppressed_finding_count"] == 1


@pytest.mark.parametrize("case", ["empty", "missing", "file", "malformed", "directory", "dangling"])
def test_project_errors_fail_closed(tmp_path, capsys, case):
    root = tmp_path
    if case == "missing":
        root = tmp_path / "missing"
    elif case == "file":
        root = tmp_path / "file"
        root.write_text("")
    elif case == "malformed":
        (root / ".mcp.json").write_text("{")
    elif case == "directory":
        (root / ".mcp.json").mkdir()
    elif case == "dangling":
        (root / ".mcp.json").symlink_to(root / "missing")
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--project", str(root), "--format", "json"])
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert str(root) in output.err


@pytest.mark.parametrize("extra", [["config.json"], ["--preset", "all"]])
def test_project_rejects_ambiguous_input(extra):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--project", "."] + extra)
    assert exc.value.code == 2
