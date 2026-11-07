# ==============================================================================
# Product:       lh-auto-remediation (lh-remediate)
# Module:        tests.test_patch_generator
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the unified diff patch generator.

Validates unified diff creation and RemediationPatch construction.
"""

from __future__ import annotations

from lh_auto_remediation.models import FindingSeverity, RemediationCategory
from lh_auto_remediation.patch_generator import create_patch, generate_unified_diff


def test_generate_unified_diff() -> None:
    """Test generating standard unified git diff between original and remediated text."""
    orig = "USER root\nCMD ['run']\n"
    rem = "USER appuser\nCMD ['run']\n"

    diff = generate_unified_diff(orig, rem, "Dockerfile")
    assert "--- a/Dockerfile" in diff
    assert "+++ b/Dockerfile" in diff
    assert "-USER root" in diff
    assert "+USER appuser" in diff


def test_create_patch_instance() -> None:
    """Test constructing a structured RemediationPatch instance."""
    orig = "ssl = off\n"
    rem = "ssl = on\n"

    patch = create_patch(
        rule_id="LH-REM-007",
        target="postgresql.conf",
        original_snippet="ssl = off",
        remediated_snippet="ssl = on",
        original_content=orig,
        remediated_content=rem,
        description="Enable SSL in database configuration",
        line_number=5,
    )

    assert patch.rule_id == "LH-REM-007"
    assert patch.severity == FindingSeverity.HIGH
    assert patch.category == RemediationCategory.DATABASE_SECURITY
    assert patch.line_number == 5
    assert "-ssl = off" in patch.unified_diff
    assert "+ssl = on" in patch.unified_diff
    patch_dict = patch.to_dict()
    assert patch_dict["rule_id"] == "LH-REM-007"
