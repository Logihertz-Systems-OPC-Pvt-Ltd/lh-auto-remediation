# ==============================================================================
# Product:       lh-auto-remediation (lh-remediate)
# Module:        src.lh_auto_remediation.exporters
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Exporters for remediation audit reports in table, JSON, and SARIF v2.1.0 formats.

Provides terminal presentation via Rich, machine-readable structured JSON,
and OASIS SARIF v2.1.0 output for CI/CD, remediation automation, and review workflows.
"""

from __future__ import annotations

import io
import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_auto_remediation.models import (
    RULES_REGISTRY,
    FindingSeverity,
    RemediationPatch,
    RemediationReport,
)

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"


class OutputFormat(StrEnum):
    """Supported output formats for automated remediation reports."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


def _severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map FindingSeverity to OASIS SARIF rule level."""
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        return "error"
    if severity == FindingSeverity.MEDIUM:
        return "warning"
    return "note"


def _get_severity_badge(severity: FindingSeverity) -> Text:
    """Return styled Rich Text badge for finding severity."""
    if severity == FindingSeverity.CRITICAL:
        return Text("CRITICAL", style="bold white on red")
    if severity == FindingSeverity.HIGH:
        return Text("HIGH", style="bold red")
    if severity == FindingSeverity.MEDIUM:
        return Text("MEDIUM", style="bold yellow")
    if severity == FindingSeverity.LOW:
        return Text("LOW", style="bold cyan")
    return Text(severity.value, style="bold")


def render_table_report(report: RemediationReport, console: Console | None = None) -> str:
    # --- Rich Terminal Table Presentation Layout ---
    # Renders structured security findings with ANSI color highlights,
    # severity-coded badges, file locations, and executive posture summaries.
    """Render complete RemediationReport to terminal or capture to string."""
    report.compute_summary()
    string_io = io.StringIO()
    target_console = console or Console(file=string_io, color_system="auto", width=120)

    title = "lh-auto-remediation: Automated Security Patch & Hardening Engine"
    subtitle = f"Generated at {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    target_console.print(
        Panel(
            Text(f"{title}\n{subtitle}", justify="center", style="bold cyan"),
            border_style="cyan",
        )
    )

    # 1. Executive Summary Table
    summary = report.summary
    summary_table = Table(title="Remediation Executive Summary", border_style="blue")
    summary_table.add_column("Targets Analyzed", justify="right")
    summary_table.add_column("Files Scanned", justify="right")
    summary_table.add_column("Patches Generated", justify="right")
    summary_table.add_column("Critical", justify="right")
    summary_table.add_column("High", justify="right")
    summary_table.add_column("Medium", justify="right")
    summary_table.add_column("Low", justify="right")

    crit_style = "bold red" if summary.get("critical", 0) > 0 else "dim"
    high_style = "bold red" if summary.get("high", 0) > 0 else "dim"
    med_style = "bold yellow" if summary.get("medium", 0) > 0 else "dim"
    low_style = "bold cyan" if summary.get("low", 0) > 0 else "dim"

    summary_table.add_row(
        str(summary.get("total_targets", 0)),
        str(summary.get("files_scanned", 0)),
        str(summary.get("total_patches", 0)),
        f"[{crit_style}]{summary.get('critical', 0)}[/{crit_style}]",
        f"[{high_style}]{summary.get('high', 0)}[/{high_style}]",
        f"[{med_style}]{summary.get('medium', 0)}[/{med_style}]",
        f"[{low_style}]{summary.get('low', 0)}[/{low_style}]",
    )
    target_console.print(summary_table)

    all_patches: list[RemediationPatch] = []
    for res in report.results:
        all_patches.extend(res.patches)

    if not all_patches:
        target_console.print(
            Panel(
                Text(
                    "✔ Clean Scan: Target configurations match hardening baselines. "
                    "Zero remediation patches required.",
                    justify="center",
                    style="bold green",
                ),
                border_style="green",
            )
        )
    else:
        patches_table = Table(
            title=f"Automated Remediation Patches ({len(all_patches)})",
            border_style="red"
            if summary.get("critical", 0) > 0 or summary.get("high", 0) > 0
            else "yellow",
        )
        patches_table.add_column("Target", style="bold white")
        patches_table.add_column("Rule ID", style="bold magenta", no_wrap=True)
        patches_table.add_column("Severity", justify="center", no_wrap=True)
        patches_table.add_column("Category", style="cyan")
        patches_table.add_column("Remediation Description")

        for p in all_patches:
            target_label = Path(p.target).name if len(p.target) > 28 else p.target
            patches_table.add_row(
                target_label,
                p.rule_id,
                _get_severity_badge(p.severity),
                p.category.value,
                p.description,
            )
        target_console.print(patches_table)

    for res in report.results:
        if res.error_message:
            target_console.print(
                Panel(
                    Text(
                        f"Scan Error on '{res.target}': {res.error_message}",
                        style="bold red",
                    ),
                    border_style="red",
                )
            )

    return string_io.getvalue()


def export_json(report: RemediationReport, indent: int = 2) -> str:
    """Export RemediationReport as structured JSON string."""
    return json.dumps(report.to_dict(), indent=indent)


def export_sarif(report: RemediationReport, indent: int = 2) -> str:
    # --- OASIS SARIF v2.1.0 Compliance Exporter ---
    # Serializes audit results into standard SARIF JSON format for native
    # GitHub Code Scanning, GitLab Security Dashboard, and IDE integrations.
    """Export RemediationReport as OASIS SARIF v2.1.0 document."""
    report.compute_summary()

    rules_meta: list[dict[str, Any]] = []
    for r_def in sorted(RULES_REGISTRY.values(), key=lambda r: r.rule_id):
        rules_meta.append(
            {
                "id": r_def.rule_id,
                "name": r_def.title.replace(" ", ""),
                "shortDescription": {"text": r_def.title},
                "fullDescription": {"text": r_def.description},
                "defaultConfiguration": {"level": _severity_to_sarif_level(r_def.severity)},
                "help": {
                    "text": f"Remediation: {r_def.remediation}",
                    "markdown": f"**Remediation**: {r_def.remediation}",
                },
                "properties": {
                    "severity": r_def.severity.value,
                    "category": r_def.category.value,
                },
            }
        )

    sarif_results: list[dict[str, Any]] = []
    for res in report.results:
        for p in res.patches:
            line = p.line_number or 1
            sarif_results.append(
                {
                    "ruleId": p.rule_id,
                    "level": _severity_to_sarif_level(p.severity),
                    "message": {"text": p.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": p.target,
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": line,
                                    "startColumn": 1,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "severity": p.severity.value,
                        "category": p.category.value,
                        "unified_diff": p.unified_diff,
                        "remediation": p.remediation_instructions,
                    },
                }
            )

    sarif_payload = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-auto-remediation",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-auto-remediation",
                        "rules": rules_meta,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_payload, indent=indent)
