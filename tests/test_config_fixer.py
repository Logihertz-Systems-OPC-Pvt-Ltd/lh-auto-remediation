# ==============================================================================
# Product:       lh-auto-remediation (lh-remediate)
# Module:        tests.test_config_fixer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for configuration fixer and automated remediation rules.

Validates rules LH-REM-001 through LH-REM-010, clean baseline handling,
and file-specific remediation logic across Docker, K8s, Terraform, Linux, DB, and code.
"""

from __future__ import annotations

from pathlib import Path

from lh_auto_remediation.config_fixer import remediate_file, remediate_target
from lh_auto_remediation.models import RULES_REGISTRY, FindingSeverity


def test_clean_hardened_project(clean_hardened_project: Path) -> None:
    """Validate that a fully hardened project generates zero remediation patches."""
    result = remediate_target(clean_hardened_project)
    assert result.error_message is None
    assert result.files_scanned == 1
    assert result.patches_count == 0
    assert len(result.patches) == 0


def test_dockerfile_remediations(insecure_dockerfile: Path) -> None:
    """Validate Dockerfile remediations: REM-001, REM-002, REM-003, REM-008, REM-010."""
    patches = remediate_file(insecure_dockerfile)
    rule_ids = {p.rule_id for p in patches}

    # LH-REM-001: Root execution fix
    assert "LH-REM-001" in rule_ids
    # LH-REM-002: Unpinned base image fix
    assert "LH-REM-002" in rule_ids
    # LH-REM-003: Hardcoded secret externalization
    assert "LH-REM-003" in rule_ids
    # LH-REM-008: ADD to COPY & apt cache cleanup
    assert "LH-REM-008" in rule_ids
    # LH-REM-010: HEALTHCHECK injection
    assert "LH-REM-010" in rule_ids


def test_compose_and_k8s_remediations(insecure_compose_and_k8s: Path) -> None:
    """Validate Compose and K8s remediations: REM-003, REM-004, REM-010."""
    result = remediate_target(insecure_compose_and_k8s)
    rule_ids = {p.rule_id for p in result.patches}

    # LH-REM-003: Password externalization
    assert "LH-REM-003" in rule_ids
    # LH-REM-004: Privileged container & securityContext hardening
    assert "LH-REM-004" in rule_ids
    # LH-REM-010: automountServiceAccountToken: false
    assert "LH-REM-010" in rule_ids


def test_terraform_remediations(insecure_terraform_file: Path) -> None:
    """Validate Terraform HCL lockdown: REM-005."""
    patches = remediate_file(insecure_terraform_file)
    rule_ids = {p.rule_id for p in patches}
    assert "LH-REM-005" in rule_ids

    diffs = " ".join(p.unified_diff for p in patches)
    assert 'acl = "private"' in diffs
    assert "encrypted = true" in diffs
    assert 'cidr_blocks = ["10.0.0.0/8"]' in diffs


def test_kernel_and_db_remediations(insecure_kernel_and_db: Path) -> None:
    """Validate sysctl and database remediations: REM-006 and REM-007."""
    result = remediate_target(insecure_kernel_and_db)
    rule_ids = {p.rule_id for p in result.patches}

    # LH-REM-006: sysctl hardening
    assert "LH-REM-006" in rule_ids
    # LH-REM-007: database binding, SSL, auth hardening
    assert "LH-REM-007" in rule_ids


def test_code_and_api_remediations(insecure_code_and_api: Path) -> None:
    """Validate Python code safety and HTTP-to-HTTPS upgrade: REM-008 and REM-009."""
    result = remediate_target(insecure_code_and_api)
    rule_ids = {p.rule_id for p in result.patches}

    # LH-REM-008: yaml.load -> yaml.safe_load
    assert "LH-REM-008" in rule_ids
    # LH-REM-009: http:// -> https://
    assert "LH-REM-009" in rule_ids


def test_nonexistent_path() -> None:
    """Test remediate_target returns error when path does not exist."""
    res = remediate_target("/nonexistent/file/path")
    assert res.error_message is not None
    assert "does not exist" in res.error_message


def test_all_ten_rules_in_registry() -> None:
    """Verify all 10 LH-REM rules are registered with valid metadata."""
    assert len(RULES_REGISTRY) == 10
    for idx in range(1, 11):
        rule_id = f"LH-REM-{idx:03d}"
        assert rule_id in RULES_REGISTRY
        r_def = RULES_REGISTRY[rule_id]
        assert r_def.severity in (
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH,
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
        )
