# ==============================================================================
# Product:       lh-auto-remediation (lh-remediate)
# Module:        src.lh_auto_remediation.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and rule definitions for lh-auto-remediation.

Provides structured types for remediation rules (LH-REM-001 to LH-REM-010),
unified diff patches, configuration fixes, and consolidated remediation reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity classification for remediable security flaws."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparisons."""
        order = {
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
            FindingSeverity.CRITICAL: 4,
        }
        return order[self]

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


class RemediationCategory(StrEnum):
    """Categories of automated security remediation."""

    CONTAINER_HARDENING = "Container Hardening"
    SUPPLY_CHAIN_HYGIENE = "Supply Chain Hygiene"
    SECRET_HYGIENE = "Secret Hygiene"  # nosec B105
    WORKLOAD_HARDENING = "Workload Hardening"
    CLOUD_IAC_LOCKDOWN = "Cloud IaC Lockdown"
    KERNEL_HARDENING = "Host & Kernel Baseline"
    DATABASE_SECURITY = "Database Security"
    CODE_SAFETY = "Code & Command Safety"
    TRANSPORT_SECURITY = "Transport Security"
    OPERATIONAL_RESILIENCE = "Operational Resilience"


@dataclass
class RemediationPatch:
    """Specific automated remediation patch with unified git diff."""

    rule_id: str
    severity: FindingSeverity
    category: RemediationCategory
    title: str
    target: str
    description: str
    original_snippet: str
    remediated_snippet: str
    unified_diff: str
    remediation_instructions: str
    line_number: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert remediation patch to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "target": self.target,
            "line_number": self.line_number,
            "description": self.description,
            "original_snippet": self.original_snippet,
            "remediated_snippet": self.remediated_snippet,
            "unified_diff": self.unified_diff,
            "remediation_instructions": self.remediation_instructions,
            "metadata": self.metadata,
        }


@dataclass
class RemediationRuleDefinition:
    """Formal definition for an automated remediation rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: RemediationCategory
    description: str
    remediation: str


@dataclass
class ScanTargetResult:
    """Remediation results for an audited file or directory."""

    target: str
    files_scanned: int = 0
    patches_count: int = 0
    patches: list[RemediationPatch] = field(default_factory=list)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "patches_count": self.patches_count,
            "error_message": self.error_message,
            "patches": [p.to_dict() for p in self.patches],
        }


@dataclass
class RemediationReport:
    """Consolidated automated remediation audit report."""

    report_type: str = "auto_remediation_audit"
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    parameters: dict[str, Any] = field(default_factory=dict)
    results: list[ScanTargetResult] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    category_breakdown: dict[str, int] = field(default_factory=dict)

    def compute_summary(self) -> None:
        """Compute aggregated counts by severity and category."""
        counts = {
            "total_targets": len(self.results),
            "files_scanned": sum(r.files_scanned for r in self.results),
            "total_patches": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        cats: dict[str, int] = {c.value: 0 for c in RemediationCategory}

        for res in self.results:
            for p in res.patches:
                counts["total_patches"] += 1
                if p.severity == FindingSeverity.CRITICAL:
                    counts["critical"] += 1
                elif p.severity == FindingSeverity.HIGH:
                    counts["high"] += 1
                elif p.severity == FindingSeverity.MEDIUM:
                    counts["medium"] += 1
                elif p.severity == FindingSeverity.LOW:
                    counts["low"] += 1

                cats[p.category.value] = cats.get(p.category.value, 0) + 1

        self.summary = counts
        self.category_breakdown = cats

    def has_failures(self, threshold: FindingSeverity | None) -> bool:
        """Check if any remediation patch meets or exceeds the failure threshold."""
        if threshold is None:
            return False
        for res in self.results:
            for p in res.patches:
                if p.severity.meets_threshold(threshold):
                    return True
        return False

    def filter_min_severity(self, min_sev: FindingSeverity) -> None:
        """Filter out patches below the specified minimum severity."""
        for res in self.results:
            res.patches = [p for p in res.patches if p.severity.meets_threshold(min_sev)]
            res.patches_count = len(res.patches)
        self.compute_summary()

    def to_dict(self) -> dict[str, Any]:
        """Convert complete remediation report to dictionary."""
        self.compute_summary()
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "parameters": self.parameters,
            "summary": self.summary,
            "category_breakdown": self.category_breakdown,
            "results": [r.to_dict() for r in self.results],
        }


RULES_REGISTRY: dict[str, RemediationRuleDefinition] = {
    "LH-REM-001": RemediationRuleDefinition(
        rule_id="LH-REM-001",
        title="Container Root Execution Fix",
        severity=FindingSeverity.CRITICAL,
        category=RemediationCategory.CONTAINER_HARDENING,
        description=(
            "Detects missing non-root USER directive or explicit USER root in Dockerfile and "
            "injects a non-root user switching block before process execution."
        ),
        remediation=(
            "Create a non-privileged group and user and append 'USER appuser' in Dockerfile."
        ),
    ),
    "LH-REM-002": RemediationRuleDefinition(
        rule_id="LH-REM-002",
        title="Unpinned Base Image & Dependency Fix",
        severity=FindingSeverity.HIGH,
        category=RemediationCategory.SUPPLY_CHAIN_HYGIENE,
        description=(
            "Detects mutable :latest base image tags or unpinned package version specifiers and "
            "replaces them with immutable version tags or exact pins."
        ),
        remediation="Pin base images to stable LTS tags and pin dependencies with '=='.",
    ),
    "LH-REM-003": RemediationRuleDefinition(
        rule_id="LH-REM-003",
        title="Hardcoded Secret Externalization",
        severity=FindingSeverity.CRITICAL,
        category=RemediationCategory.SECRET_HYGIENE,
        description=(
            "Detects hardcoded passwords, tokens, or private keys in configs, Compose, or "
            "Dockerfile and externalizes them to environment variable references (${VAR_NAME})."
        ),
        remediation="Externalize plaintext credentials to environment variable placeholders.",
    ),
    "LH-REM-004": RemediationRuleDefinition(
        rule_id="LH-REM-004",
        title="Container & Kubernetes SecurityContext Hardening",
        severity=FindingSeverity.HIGH,
        category=RemediationCategory.WORKLOAD_HARDENING,
        description=(
            "Remediates privileged container execution, shared host namespaces (PID/net), "
            "or missing securityContext with allowPrivilegeEscalation: false and drop: [ALL]."
        ),
        remediation="Enforce least privilege securityContext on containers and Pod specs.",
    ),
    "LH-REM-005": RemediationRuleDefinition(
        rule_id="LH-REM-005",
        title="Cloud Storage & Ingress Lockdown",
        severity=FindingSeverity.CRITICAL,
        category=RemediationCategory.CLOUD_IAC_LOCKDOWN,
        description=(
            "Remediates public S3 ACLs (public-read), unencrypted storage resources, and "
            "unrestricted 0.0.0.0/0 administrative ingress in Terraform HCL."
        ),
        remediation=(
            "Set S3 ACL to private, enable server-side encryption, and restrict SSH/RDP CIDRs."
        ),
    ),
    "LH-REM-006": RemediationRuleDefinition(
        rule_id="LH-REM-006",
        title="Linux Kernel sysctl Hardening Patch",
        severity=FindingSeverity.HIGH,
        category=RemediationCategory.KERNEL_HARDENING,
        description=(
            "Detects unhardened Linux kernel sysctl parameters (ASLR disabled, SYN cookies off, "
            "kptr_restrict off, IP forwarding on) and generates hardened sysctl.conf overrides."
        ),
        remediation="Configure compliant kernel security sysctl settings in sysctl.conf.",
    ),
    "LH-REM-007": RemediationRuleDefinition(
        rule_id="LH-REM-007",
        title="Database Binding & Auth Hardening Patch",
        severity=FindingSeverity.HIGH,
        category=RemediationCategory.DATABASE_SECURITY,
        description=(
            "Remediates wildcard database interface bindings (0.0.0.0, *), disabled SSL "
            "transport, and insecure pg_hba trust authentication to localhost, ssl = on, "
            "and scram-sha-256."
        ),
        remediation=(
            "Bind databases to 127.0.0.1, enforce SSL transport, and require scram-sha-256."
        ),
    ),
    "LH-REM-008": RemediationRuleDefinition(
        rule_id="LH-REM-008",
        title="Unsafe Command & Code Sink Replacement",
        severity=FindingSeverity.HIGH,
        category=RemediationCategory.CODE_SAFETY,
        description=(
            "Replaces Dockerfile ADD with COPY, appends package cache cleanups (rm -rf "
            "/var/lib/apt/lists/*), and swaps unsafe yaml.load() with yaml.safe_load()."
        ),
        remediation="Use COPY instead of ADD, clean package caches, and use yaml.safe_load.",
    ),
    "LH-REM-009": RemediationRuleDefinition(
        rule_id="LH-REM-009",
        title="Cleartext Transport & API Policy Upgrade",
        severity=FindingSeverity.MEDIUM,
        category=RemediationCategory.TRANSPORT_SECURITY,
        description=(
            "Remediates cleartext http:// URLs to https:// across API specs and configurations, "
            "and injects baseline rate-limiting policy headers."
        ),
        remediation="Upgrade endpoints to HTTPS and configure API rate limiting.",
    ),
    "LH-REM-010": RemediationRuleDefinition(
        rule_id="LH-REM-010",
        title="Operational Resilience Patch",
        severity=FindingSeverity.LOW,
        category=RemediationCategory.OPERATIONAL_RESILIENCE,
        description=(
            "Injects missing HEALTHCHECK probes into Dockerfile configurations and disables "
            "automountServiceAccountToken in Kubernetes workload manifests."
        ),
        remediation="Add Dockerfile HEALTHCHECK instruction and disable default token automount.",
    ),
}
