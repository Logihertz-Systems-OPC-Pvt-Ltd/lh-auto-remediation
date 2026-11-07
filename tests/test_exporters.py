# ==============================================================================
# Product:       lh-auto-remediation (lh-remediate)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for remediation report exporters (Table, JSON, SARIF v2.1.0).

Validates terminal presentation, structured JSON schema, and SARIF v2.1.0 output.
"""

from __future__ import annotations

import json

from lh_auto_remediation.exporters import (
    _get_severity_badge,
    _severity_to_sarif_level,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_auto_remediation.models import (
    FindingSeverity,
    RemediationCategory,
    RemediationPatch,
    RemediationReport,
    ScanTargetResult,
)


def _build_sample_report(has_patches: bool = True) -> RemediationReport:
    """Helper creating a sample RemediationReport for exporter tests."""
    patches = []
    if has_patches:
        patches = [
            RemediationPatch(
                rule_id="LH-REM-001",
                severity=FindingSeverity.CRITICAL,
                category=RemediationCategory.CONTAINER_HARDENING,
                title="Container Root Execution Fix",
                target="Dockerfile",
                description="Enforce non-root user execution in container",
                original_snippet="USER root",
                remediated_snippet="USER appuser",
                unified_diff="--- a/Dockerfile\n+++ b/Dockerfile\n-USER root\n+USER appuser\n",
                remediation_instructions="Switch to non-root USER",
                line_number=5,
            ),
            RemediationPatch(
                rule_id="LH-REM-005",
                severity=FindingSeverity.CRITICAL,
                category=RemediationCategory.CLOUD_IAC_LOCKDOWN,
                title="Cloud Storage & Ingress Lockdown",
                target="main.tf",
                description="Restrict public S3 bucket ACL to private",
                original_snippet='acl = "public-read"',
                remediated_snippet='acl = "private"',
                unified_diff=(
                    "--- a/main.tf\n+++ b/main.tf\n-acl = 'public-read'\n+acl = 'private'\n"
                ),
                remediation_instructions="Set S3 ACL to private",
                line_number=3,
            ),
        ]

    res = ScanTargetResult(
        target="/app",
        files_scanned=2 if has_patches else 1,
        patches_count=len(patches),
        patches=patches,
    )
    report = RemediationReport(
        results=[res],
        parameters={"format": "table"},
    )
    report.compute_summary()
    return report


def test_render_table_report_with_patches() -> None:
    """Test table rendering when remediation patches are generated."""
    report = _build_sample_report(has_patches=True)
    rendered = render_table_report(report)

    assert "lh-auto-remediation" in rendered
    assert "Remediation Executive Summary" in rendered
    assert "Automated Remediation Patches" in rendered
    assert "LH-REM-001" in rendered
    assert "CRITICAL" in rendered
    assert "Dockerfile" in rendered


def test_render_table_report_clean() -> None:
    """Test table rendering for clean scan with zero patches needed."""
    report = _build_sample_report(has_patches=False)
    rendered = render_table_report(report)

    assert "Clean Scan" in rendered
    assert "Zero remediation patches required" in rendered


def test_export_json_schema() -> None:
    """Test JSON export schema conformity."""
    report = _build_sample_report(has_patches=True)
    json_str = export_json(report)
    data = json.loads(json_str)

    assert data["report_type"] == "auto_remediation_audit"
    assert "summary" in data
    assert data["summary"]["total_patches"] == 2
    assert data["summary"]["critical"] == 2
    assert len(data["results"]) == 1
    assert len(data["results"][0]["patches"]) == 2


def test_export_sarif_schema() -> None:
    """Test SARIF v2.1.0 document structure conformity."""
    report = _build_sample_report(has_patches=True)
    sarif_str = export_sarif(report)
    data = json.loads(sarif_str)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "lh-auto-remediation"
    assert len(run["results"]) == 2
    assert run["results"][0]["ruleId"] == "LH-REM-001"
    assert run["results"][0]["level"] == "error"
    assert "unified_diff" in run["results"][0]["properties"]


def test_severity_helpers() -> None:
    """Test severity level mappings and badge styling."""
    assert _severity_to_sarif_level(FindingSeverity.CRITICAL) == "error"
    assert _severity_to_sarif_level(FindingSeverity.HIGH) == "error"
    assert _severity_to_sarif_level(FindingSeverity.MEDIUM) == "warning"
    assert _severity_to_sarif_level(FindingSeverity.LOW) == "note"

    badge = _get_severity_badge(FindingSeverity.CRITICAL)
    assert "CRITICAL" in badge.plain
