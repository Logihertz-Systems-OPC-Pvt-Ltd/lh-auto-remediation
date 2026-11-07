# ==============================================================================
# Product:       lh-auto-remediation (lh-remediate)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the lh-auto-remediation command-line interface.

Validates CLI commands 'scan' and 'rules', parameter flags, output formats,
and exit status codes (0, 1, 2) using typer.testing.CliRunner.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_auto_remediation.cli import app

runner = CliRunner()
CLI_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_rules_command() -> None:
    """Test 'rules' command lists all LH-REM rules and exits with 0."""
    result = runner.invoke(app, ["rules"], env=CLI_ENV)
    assert result.exit_code == 0
    assert "LH-REM-001" in result.stdout
    assert "LH-REM-010" in result.stdout
    assert "Container Root Execution Fix" in result.stdout


def test_cli_scan_clean_project(clean_hardened_project: Path) -> None:
    """Test scanning a fully hardened project returns exit code 0 and clean banner."""
    result = runner.invoke(app, ["scan", str(clean_hardened_project)], env=CLI_ENV)
    assert result.exit_code == 0
    assert "Clean Scan" in result.stdout


def test_cli_scan_insecure_dockerfile_fails(insecure_dockerfile: Path) -> None:
    """Test scanning an insecure Dockerfile exits with 1 when patches meet fail-on threshold."""
    result = runner.invoke(
        app,
        ["scan", str(insecure_dockerfile), "--fail-on", "HIGH"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    assert "LH-REM-001" in result.stdout


def test_cli_scan_fail_on_threshold(tmp_path: Path) -> None:
    """Test fail-on threshold suppresses failure exit if findings are below threshold."""
    # Create an API file that only triggers REM-009 (MEDIUM)
    api_file = tmp_path / "api.json"
    api_file.write_text('{"url": "http://api.local/v1"}', encoding="utf-8")

    result = runner.invoke(
        app,
        ["scan", str(api_file), "--fail-on", "CRITICAL"],
        env=CLI_ENV,
    )
    assert result.exit_code == 0


def test_cli_scan_format_json(insecure_dockerfile: Path) -> None:
    """Test JSON output formatting to stdout."""
    result = runner.invoke(
        app,
        ["scan", str(insecure_dockerfile), "--format", "json"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["report_type"] == "auto_remediation_audit"
    assert data["summary"]["critical"] >= 1


def test_cli_scan_format_sarif(insecure_dockerfile: Path) -> None:
    """Test SARIF v2.1.0 output formatting to stdout."""
    result = runner.invoke(
        app,
        ["scan", str(insecure_dockerfile), "--format", "sarif"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "lh-auto-remediation"


def test_cli_scan_output_file(clean_hardened_project: Path, tmp_path: Path) -> None:
    """Test writing remediation report directly to an output file."""
    out_file = tmp_path / "reports" / "remediation.json"
    result = runner.invoke(
        app,
        ["scan", str(clean_hardened_project), "--format", "json", "--output", str(out_file)],
        env=CLI_ENV,
    )
    assert result.exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["report_type"] == "auto_remediation_audit"
    assert data["summary"]["total_patches"] == 0


def test_cli_scan_nonexistent_path() -> None:
    """Test scanning a nonexistent path exits with code 2."""
    result = runner.invoke(app, ["scan", "/nonexistent/config/path"], env=CLI_ENV)
    assert result.exit_code == 2
    assert "Error: Target path '/nonexistent/config/path' does not exist." in result.stdout


def test_cli_min_severity_filter(insecure_dockerfile: Path) -> None:
    """Test min-severity filtering excludes lower severity patches."""
    result = runner.invoke(
        app,
        [
            "scan",
            str(insecure_dockerfile),
            "--format",
            "json",
            "--min-severity",
            "CRITICAL",
        ],
        env=CLI_ENV,
    )
    data = json.loads(result.stdout)
    for res in data["results"]:
        for p in res["patches"]:
            assert p["severity"] == "CRITICAL"
