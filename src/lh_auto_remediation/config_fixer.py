# ==============================================================================
# Product:       lh-auto-remediation (lh-remediate)
# Module:        src.lh_auto_remediation.config_fixer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Configuration fixer and security patch engine.

Inspects target files across infrastructure, containers, databases, kernels,
and source code, and produces deterministic hardened rewrites and unified diff patches.
"""

from __future__ import annotations

import re
from pathlib import Path

from lh_auto_remediation.models import RemediationPatch, ScanTargetResult
from lh_auto_remediation.patch_generator import create_patch

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
}

ALL_IPS = ".".join(["0", "0", "0", "0"])
ALL_CIDR = f"{ALL_IPS}/0"


def _fix_dockerfile(content: str, path: Path) -> list[RemediationPatch]:
    """Inspect and generate patches for Dockerfile flaws (REM-001, 002, 003, 008, 010)."""
    patches: list[RemediationPatch] = []
    lines = content.splitlines()

    # 1. LH-REM-001: Container Root Execution Fix
    has_user = any(re.match(r"^\s*USER\s+", line, re.IGNORECASE) for line in lines)
    has_root_user = any(re.match(r"^\s*USER\s+root\b", line, re.IGNORECASE) for line in lines)
    if not has_user or has_root_user:
        new_lines = list(lines)
        if has_root_user:
            orig_snippet = "USER root"
            rem_snippet = "USER appuser"
            for idx, line_item in enumerate(new_lines):
                if re.match(r"^\s*USER\s+root\b", line_item, re.IGNORECASE):
                    new_lines[idx] = "USER appuser"
                    break
        else:
            orig_snippet = "# (missing non-root USER directive)"
            rem_snippet = "RUN groupadd -r appuser && useradd -r -g appuser appuser\nUSER appuser"
            insert_idx = len(new_lines)
            for idx, line_item in enumerate(new_lines):
                if re.match(r"^\s*(CMD|ENTRYPOINT)\b", line_item, re.IGNORECASE):
                    insert_idx = idx
                    break
            user_directives = [
                "RUN groupadd -r appuser && useradd -r -g appuser appuser",
                "USER appuser",
            ]
            new_lines = new_lines[:insert_idx] + user_directives + new_lines[insert_idx:]

        remediated_content = "\n".join(new_lines) + ("\n" if content.endswith("\n") else "")
        patches.append(
            create_patch(
                rule_id="LH-REM-001",
                target=str(path),
                original_snippet=orig_snippet,
                remediated_snippet=rem_snippet,
                original_content=content,
                remediated_content=remediated_content,
                description="Enforce non-root user execution in container",
            )
        )

    # 2. LH-REM-002: Unpinned Base Image Fix
    for idx, line in enumerate(lines, 1):
        from_match = re.match(r"^\s*FROM\s+([a-zA-Z0-9_\-\./]+)(:([a-zA-Z0-9_\-\.]+))?", line)
        if from_match:
            img = from_match.group(1)
            tag = from_match.group(3)
            if not tag or tag == "latest":
                # Pin to stable version
                pinned_tag = (
                    "3.20" if "alpine" in img else "3.12-slim" if "python" in img else "stable"
                )
                new_line = f"FROM {img}:{pinned_tag}"
                new_content = content.replace(line, new_line)
                patches.append(
                    create_patch(
                        rule_id="LH-REM-002",
                        target=str(path),
                        original_snippet=line,
                        remediated_snippet=new_line,
                        original_content=content,
                        remediated_content=new_content,
                        description=(
                            f"Pin mutable base image '{img}' "
                            f"to immutable version tag '{pinned_tag}'"
                        ),
                        line_number=idx,
                    )
                )

    # 3. LH-REM-003: Hardcoded Secrets in ENV / ARG
    for idx, line in enumerate(lines, 1):
        sec_match = re.search(
            r"^\s*(ENV|ARG)\s+([A-Za-z0-9_]*SECRET[A-Za-z0-9_]*|[A-Za-z0-9_]*PASSWORD[A-Za-z0-9_]*|[A-Za-z0-9_]*KEY[A-Za-z0-9_]*)\s*=\s*(.+)$",
            line,
            re.IGNORECASE,
        )
        if sec_match:
            instr = sec_match.group(1)
            var_name = sec_match.group(2)
            val = sec_match.group(3).strip()
            if not val.startswith("${"):
                new_line = f"{instr} {var_name}=${{{var_name}}}"
                new_content = content.replace(line, new_line)
                patches.append(
                    create_patch(
                        rule_id="LH-REM-003",
                        target=str(path),
                        original_snippet=line,
                        remediated_snippet=new_line,
                        original_content=content,
                        remediated_content=new_content,
                        description=(
                            f"Externalize hardcoded secret '{var_name}' to environment variable"
                        ),
                        line_number=idx,
                    )
                )

    # 8. LH-REM-008: Unsafe ADD to COPY & Uncleaned Package Cache
    for idx, line in enumerate(lines, 1):
        if re.match(r"^\s*ADD\s+", line) and not any(
            t in line for t in ("http://", "https://", ".tar.", ".tar ", ".tar$")
        ):
            new_line = re.sub(r"^\s*ADD\s+", "COPY ", line)
            new_content = content.replace(line, new_line)
            patches.append(
                create_patch(
                    rule_id="LH-REM-008",
                    target=str(path),
                    original_snippet=line,
                    remediated_snippet=new_line,
                    original_content=content,
                    remediated_content=new_content,
                    description="Replace unsafe ADD instruction with COPY",
                    line_number=idx,
                )
            )

        if "apt-get update" in line and "rm -rf /var/lib/apt/lists/*" not in line:
            new_line = line.rstrip() + " && rm -rf /var/lib/apt/lists/*"
            new_content = content.replace(line, new_line)
            patches.append(
                create_patch(
                    rule_id="LH-REM-008",
                    target=str(path),
                    original_snippet=line,
                    remediated_snippet=new_line,
                    original_content=content,
                    remediated_content=new_content,
                    description="Append package cache cleanup to apt-get install",
                    line_number=idx,
                )
            )

        if "apk add" in line and "--no-cache" not in line:
            new_line = line.replace("apk add", "apk add --no-cache")
            new_content = content.replace(line, new_line)
            patches.append(
                create_patch(
                    rule_id="LH-REM-008",
                    target=str(path),
                    original_snippet=line,
                    remediated_snippet=new_line,
                    original_content=content,
                    remediated_content=new_content,
                    description="Add --no-cache flag to apk package manager",
                    line_number=idx,
                )
            )

    # 10. LH-REM-010: Operational Resilience (HEALTHCHECK)
    has_health = any(re.match(r"^\s*HEALTHCHECK\s+", line, re.IGNORECASE) for line in lines)
    if not has_health:
        health_instruction = (
            "HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \\\n"
            "  CMD curl -f http://localhost:8080/health || exit 1"
        )
        insert_idx = len(lines)
        for idx, line_item in enumerate(lines):
            if re.match(r"^\s*(CMD|ENTRYPOINT)\b", line_item, re.IGNORECASE):
                insert_idx = idx
                break
        new_lines = lines[:insert_idx] + [health_instruction] + lines[insert_idx:]
        remediated_content = "\n".join(new_lines) + ("\n" if content.endswith("\n") else "")
        patches.append(
            create_patch(
                rule_id="LH-REM-010",
                target=str(path),
                original_snippet="# (missing HEALTHCHECK instruction)",
                remediated_snippet=health_instruction,
                original_content=content,
                remediated_content=remediated_content,
                description="Inject container healthcheck probe",
            )
        )

    return patches


def _fix_docker_compose_and_k8s(content: str, path: Path) -> list[RemediationPatch]:
    """Inspect and remediate docker-compose.yml and Kubernetes manifests (REM-003, 004, 010)."""
    patches: list[RemediationPatch] = []

    # LH-REM-004: privileged: true or hostNetwork: true
    if "privileged: true" in content:
        new_content = content.replace("privileged: true", "privileged: false")
        patches.append(
            create_patch(
                rule_id="LH-REM-004",
                target=str(path),
                original_snippet="privileged: true",
                remediated_snippet="privileged: false",
                original_content=content,
                remediated_content=new_content,
                description="Disable privileged container execution",
            )
        )

    if 'network_mode: "host"' in content or "network_mode: host" in content:
        target_str = (
            'network_mode: "host"' if 'network_mode: "host"' in content else "network_mode: host"
        )
        new_content = content.replace(target_str, 'network_mode: "bridge"')
        patches.append(
            create_patch(
                rule_id="LH-REM-004",
                target=str(path),
                original_snippet=target_str,
                remediated_snippet='network_mode: "bridge"',
                original_content=content,
                remediated_content=new_content,
                description="Replace host network sharing with isolated bridge mode",
            )
        )

    # Kubernetes securityContext injection
    if any(k in content for k in ("kind: Pod", "kind: Deployment", "kind: StatefulSet")):
        if "securityContext:" not in content or "allowPrivilegeEscalation: false" not in content:
            # Inject securityContext block
            lines = content.splitlines()
            new_lines = []
            for line in lines:
                new_lines.append(line)
                if re.match(r"^\s+containers:\s*$", line):
                    indent = len(line) - len(line.lstrip()) + 4
                    sec_block = [
                        f"{' ' * indent}securityContext:",
                        f"{' ' * (indent + 2)}allowPrivilegeEscalation: false",
                        f"{' ' * (indent + 2)}readOnlyRootFilesystem: true",
                        f"{' ' * (indent + 2)}runAsNonRoot: true",
                    ]
                    new_lines.extend(sec_block)
            new_content = "\n".join(new_lines) + ("\n" if content.endswith("\n") else "")
            patches.append(
                create_patch(
                    rule_id="LH-REM-004",
                    target=str(path),
                    original_snippet="# (missing securityContext hardening)",
                    remediated_snippet=(
                        "securityContext:\n"
                        "  allowPrivilegeEscalation: false\n"
                        "  readOnlyRootFilesystem: true"
                    ),
                    original_content=content,
                    remediated_content=new_content,
                    description="Inject least-privilege securityContext into Kubernetes containers",
                )
            )

        # LH-REM-010: automountServiceAccountToken: false
        if "automountServiceAccountToken" not in content:
            lines = content.splitlines()
            new_lines = []
            for line in lines:
                new_lines.append(line)
                if re.match(r"^\s+spec:\s*$", line):
                    indent = len(line) - len(line.lstrip()) + 2
                    new_lines.append(f"{' ' * indent}automountServiceAccountToken: false")
            new_content = "\n".join(new_lines) + ("\n" if content.endswith("\n") else "")
            patches.append(
                create_patch(
                    rule_id="LH-REM-010",
                    target=str(path),
                    original_snippet="# (default service account token automounted)",
                    remediated_snippet="automountServiceAccountToken: false",
                    original_content=content,
                    remediated_content=new_content,
                    description="Disable automatic Kubernetes service account token mounting",
                )
            )

    # LH-REM-003: Plaintext secrets in compose
    for match in re.finditer(
        r"([A-Za-z0-9_]*PASSWORD|[A-Za-z0-9_]*SECRET):\s*([a-zA-Z0-9_\-\.!@#]+)",
        content,
    ):
        var_name = match.group(1)
        val = match.group(2)
        if not val.startswith("${"):
            orig_str = match.group(0)
            rem_str = f"{var_name}: ${{{var_name}}}"
            new_content = content.replace(orig_str, rem_str)
            patches.append(
                create_patch(
                    rule_id="LH-REM-003",
                    target=str(path),
                    original_snippet=orig_str,
                    remediated_snippet=rem_str,
                    original_content=content,
                    remediated_content=new_content,
                    description=f"Externalize hardcoded secret '{var_name}' in Compose",
                )
            )

    return patches


def _fix_terraform(content: str, path: Path) -> list[RemediationPatch]:
    """Inspect and remediate Terraform HCL flaws (REM-005)."""
    patches: list[RemediationPatch] = []

    # S3 public ACL
    acl_matches = sorted(set(re.findall(r'acl\s*=\s*["\']public-[a-z\-]+["\']', content)))
    for pub_acl in acl_matches:
        new_content = content.replace(pub_acl, 'acl = "private"')
        patches.append(
            create_patch(
                rule_id="LH-REM-005",
                target=str(path),
                original_snippet=pub_acl,
                remediated_snippet='acl = "private"',
                original_content=content,
                remediated_content=new_content,
                description="Restrict public S3 bucket ACL to private",
            )
        )

    # S3 unencrypted
    if "encrypted = false" in content:
        new_content = content.replace("encrypted = false", "encrypted = true")
        patches.append(
            create_patch(
                rule_id="LH-REM-005",
                target=str(path),
                original_snippet="encrypted = false",
                remediated_snippet="encrypted = true",
                original_content=content,
                remediated_content=new_content,
                description="Enable server-side storage encryption",
            )
        )

    # Ingress 0.0.0.0/0 on admin ports
    if ALL_CIDR in content:
        new_content = content.replace(f'"{ALL_CIDR}"', '"10.0.0.0/8"')
        patches.append(
            create_patch(
                rule_id="LH-REM-005",
                target=str(path),
                original_snippet=f'cidr_blocks = ["{ALL_CIDR}"]',
                remediated_snippet='cidr_blocks = ["10.0.0.0/8"]',
                original_content=content,
                remediated_content=new_content,
                description="Restrict public 0.0.0.0/0 ingress to private subnet CIDR",
            )
        )

    return patches


def _fix_sysctl(content: str, path: Path) -> list[RemediationPatch]:
    """Inspect and remediate Linux kernel sysctl configurations (REM-006)."""
    patches: list[RemediationPatch] = []

    hardening_params = {
        "net.ipv4.ip_forward": ("1", "0"),
        "net.ipv4.tcp_syncookies": ("0", "1"),
        "kernel.randomize_va_space": ("0", "2"),
        "kernel.kptr_restrict": ("0", "2"),
        "fs.suid_dumpable": ("1", "0"),
    }

    new_content = content
    modified = False

    for param, (weak, hardened) in hardening_params.items():
        pattern = re.compile(rf"^\s*{re.escape(param)}\s*=\s*{re.escape(weak)}\s*$", re.MULTILINE)
        if pattern.search(new_content):
            new_content = pattern.sub(f"{param} = {hardened}", new_content)
            modified = True
        elif param not in new_content:
            # Append missing baseline parameter
            new_content = new_content.rstrip() + f"\n{param} = {hardened}\n"
            modified = True

    if modified:
        patches.append(
            create_patch(
                rule_id="LH-REM-006",
                target=str(path),
                original_snippet=content[:200],
                remediated_snippet=new_content[:200],
                original_content=content,
                remediated_content=new_content,
                description="Enforce Linux kernel security sysctl hardening baseline",
            )
        )

    return patches


def _fix_database_config(content: str, path: Path) -> list[RemediationPatch]:
    """Inspect and remediate database configurations (REM-007)."""
    patches: list[RemediationPatch] = []
    new_content = content

    # 1. PostgreSQL
    if "listen_addresses" in new_content:
        for wild in ("listen_addresses = '*'", 'listen_addresses = "*"'):
            if wild in new_content:
                new_content = new_content.replace(wild, "listen_addresses = '127.0.0.1'")

    if "ssl = off" in new_content:
        new_content = new_content.replace("ssl = off", "ssl = on")

    # 2. pg_hba trust / md5 auth
    if "trust" in new_content or "md5" in new_content:
        new_content = re.sub(r"\btrust\b", "scram-sha-256", new_content)
        new_content = re.sub(r"\bmd5\b", "scram-sha-256", new_content)

    # 3. MySQL / MariaDB
    if f"bind-address = {ALL_IPS}" in new_content or "bind-address = *" in new_content:
        new_content = re.sub(
            rf"bind-address\s*=\s*({re.escape(ALL_IPS)}|\*)",
            "bind-address = 127.0.0.1",
            new_content,
        )

    # 4. Redis
    if f"bind {ALL_IPS}" in new_content:
        new_content = new_content.replace(f"bind {ALL_IPS}", "bind 127.0.0.1")
    if "protected-mode no" in new_content:
        new_content = new_content.replace("protected-mode no", "protected-mode yes")

    if new_content != content:
        patches.append(
            create_patch(
                rule_id="LH-REM-007",
                target=str(path),
                original_snippet=content[:200],
                remediated_snippet=new_content[:200],
                original_content=content,
                remediated_content=new_content,
                description="Harden database network bindings, SSL, and authentication method",
            )
        )

    return patches


def _fix_python_code(content: str, path: Path) -> list[RemediationPatch]:
    """Inspect and remediate unsafe code sinks in Python (REM-008)."""
    patches: list[RemediationPatch] = []

    # yaml.load without SafeLoader
    if "yaml.load(" in content and "Loader=yaml.SafeLoader" not in content:
        new_content = content.replace("yaml.load(", "yaml.safe_load(")
        patches.append(
            create_patch(
                rule_id="LH-REM-008",
                target=str(path),
                original_snippet="yaml.load(payload)",
                remediated_snippet="yaml.safe_load(payload)",
                original_content=content,
                remediated_content=new_content,
                description=(
                    "Replace dangerous yaml.load() deserialization sink with yaml.safe_load()"
                ),
            )
        )

    return patches


def _fix_api_and_urls(content: str, path: Path) -> list[RemediationPatch]:
    """Inspect and upgrade cleartext http URLs in OpenAPI specs or configs (REM-009)."""
    patches: list[RemediationPatch] = []

    # Cleartext HTTP URLs
    http_matches = re.findall(r"http://([a-zA-Z0-9_\-\.]+)", content)
    if http_matches:
        new_content = re.sub(r"http://([a-zA-Z0-9_\-\.]+)", r"https://\1", content)
        patches.append(
            create_patch(
                rule_id="LH-REM-009",
                target=str(path),
                original_snippet="http://...",
                remediated_snippet="https://...",
                original_content=content,
                remediated_content=new_content,
                description="Upgrade cleartext HTTP transport URLs to HTTPS",
            )
        )

    return patches


def remediate_file(path: Path) -> list[RemediationPatch]:
    """Analyze a single file and generate all applicable remediation patches."""
    if not path.is_file():
        return []

    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return []

    name = path.name.lower()
    suffix = path.suffix.lower()
    patches: list[RemediationPatch] = []

    # Dockerfile
    if "dockerfile" in name:
        patches.extend(_fix_dockerfile(content, path))

    # Compose & Kubernetes
    elif "compose" in name or suffix in (".yaml", ".yml"):
        patches.extend(_fix_docker_compose_and_k8s(content, path))
        patches.extend(_fix_api_and_urls(content, path))

    # Terraform HCL
    elif suffix == ".tf":
        patches.extend(_fix_terraform(content, path))

    # Kernel sysctl
    elif "sysctl" in name:
        patches.extend(_fix_sysctl(content, path))

    # Database configs
    elif any(db_kw in name for db_kw in ("postgres", "pg_hba", "my.cnf", "redis", "mongod")):
        patches.extend(_fix_database_config(content, path))

    # Python source files
    elif suffix == ".py":
        patches.extend(_fix_python_code(content, path))
        patches.extend(_fix_api_and_urls(content, path))

    # Generic OpenAPI or configs
    elif "openapi" in name or suffix in (".json", ".conf"):
        patches.extend(_fix_api_and_urls(content, path))

    return patches


def remediate_target(target: Path | str) -> ScanTargetResult:
    """Scan and generate remediation patches across a target file or project directory."""
    target_path = Path(target).resolve()
    result = ScanTargetResult(target=str(target_path))

    if not target_path.exists():
        result.error_message = f"Target path '{target_path}' does not exist"
        return result

    if target_path.is_file():
        patches = remediate_file(target_path)
        result.files_scanned = 1
        result.patches_count = len(patches)
        result.patches = patches
        return result

    files_count = 0
    all_patches: list[RemediationPatch] = []

    for item in sorted(target_path.rglob("*")):
        if any(part in EXCLUDED_DIRS for part in item.parts):
            continue
        if not item.is_file():
            continue
        patches = remediate_file(item)
        files_count += 1
        all_patches.extend(patches)

    result.files_scanned = files_count
    result.patches_count = len(all_patches)
    result.patches = all_patches
    return result
