# ==============================================================================
# Product:       lh-auto-remediation (lh-remediate)
# Module:        src.lh_auto_remediation.patch_generator
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unified git diff generator and remediation patch builder.

Transforms original and remediated content into RFC 3986 compliant unified diffs
and structured RemediationPatch instances.
"""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from lh_auto_remediation.models import (
    RULES_REGISTRY,
    RemediationPatch,
)


def generate_unified_diff(original: str, remediated: str, filename: str) -> str:
    """Generate standard unified git diff between original and remediated text."""
    orig_lines = original.splitlines(keepends=True)
    rem_lines = remediated.splitlines(keepends=True)
    # Ensure trailing newlines for difflib if text is non-empty
    if orig_lines and not orig_lines[-1].endswith("\n"):
        orig_lines[-1] += "\n"
    if rem_lines and not rem_lines[-1].endswith("\n"):
        rem_lines[-1] += "\n"

    diff_lines = list(
        difflib.unified_diff(
            orig_lines,
            rem_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            n=3,
        )
    )
    return "".join(diff_lines)


def create_patch(
    rule_id: str,
    target: str,
    original_snippet: str,
    remediated_snippet: str,
    original_content: str,
    remediated_content: str,
    description: str,
    line_number: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> RemediationPatch:
    """Construct a complete RemediationPatch with unified git diff."""
    rule_def = RULES_REGISTRY[rule_id]
    fn = Path(target).name if target else "file"
    diff_text = generate_unified_diff(original_content, remediated_content, fn)

    return RemediationPatch(
        rule_id=rule_def.rule_id,
        severity=rule_def.severity,
        category=rule_def.category,
        title=rule_def.title,
        target=target,
        description=description,
        original_snippet=original_snippet,
        remediated_snippet=remediated_snippet,
        unified_diff=diff_text,
        remediation_instructions=rule_def.remediation,
        line_number=line_number,
        metadata=metadata or {},
    )
