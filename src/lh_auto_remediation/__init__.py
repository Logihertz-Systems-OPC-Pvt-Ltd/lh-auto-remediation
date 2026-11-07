# ==============================================================================
# Product:       lh-auto-remediation (lh-remediate)
# Module:        src.lh_auto_remediation.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""lh-auto-remediation: Automated security patch generation and configuration hardening.

Logihertz Systems (OPC) Private Limited.
"""

from __future__ import annotations

from lh_auto_remediation.models import (
    RULES_REGISTRY,
    FindingSeverity,
    RemediationCategory,
    RemediationPatch,
    RemediationReport,
    ScanTargetResult,
)

__version__ = "0.1.0"
__all__ = [
    "RULES_REGISTRY",
    "FindingSeverity",
    "RemediationCategory",
    "RemediationPatch",
    "RemediationReport",
    "ScanTargetResult",
    "__version__",
]
