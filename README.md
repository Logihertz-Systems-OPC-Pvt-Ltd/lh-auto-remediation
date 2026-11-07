# lh-auto-remediation

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-auto-remediation/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-auto-remediation/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise automated security patching & hardening developed by **Logihertz Systems (OPC) Private Limited**.

Parses security audit findings and vulnerable configuration manifests (SSH, Nginx, Docker, Terraform, sysctl) to deterministically generate hardened drop-in replacements and unified Git diff remediation patches.

---

## Key Features

- **Finding-to-Patch Synthesis**: Matches static analysis findings to concrete source lines and emits valid Unified Diff (`patch -p1`) artifacts.
- **Multi-Domain Remediation**: Remediates container root execution, unpinned dependencies, exposed secrets, Kubernetes SecurityContext, and weak sysctl values.
- **Deterministic Safety Guardrails**: Validates target file syntax and preserves comments, formatting, and file structure during patching.
- **Automated Dry-Run & In-Place Execution**: Supports dry-run inspection, diff previewing, and automated in-place patch application (`--apply`).
- **Multi-Format Reporting**: Displays colorized terminal diffs, summary tables, and JSON remediation manifests.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-REM-001` | `CRITICAL` | Container Root Execution Fix — injects non-root USER directive and user creation into Dockerfile |
| `LH-REM-002` | `HIGH` | Unpinned Base Image & Dependency Fix — pins mutable :latest container tags to specific SHA256 digests |
| `LH-REM-003` | `CRITICAL` | Hardcoded Secret Externalization — replaces plaintext credentials with environment variable bindings |
| `LH-REM-004` | `HIGH` | Container & K8s SecurityContext Hardening — injects readOnlyRootFilesystem, drop ALL capabilities, and runAsNonRoot |
| `LH-REM-005` | `CRITICAL` | Cloud Storage & Ingress Lockdown — patches Terraform public S3 buckets and restricts 0.0.0.0/0 ingress rules |
| `LH-REM-006` | `HIGH` | Linux Kernel sysctl Hardening Patch — remediates insecure sysctl network parameters (ip_forward, syn_cookies) |
| `LH-REM-007` | `HIGH` | Database Binding & Auth Hardening Patch — remediates wildcard 0.0.0.0 binds and unauthenticated trust auth in pg_hba.conf |
| `LH-REM-008` | `HIGH` | Unsafe Command & Code Sink Replacement — replaces dangerous shell exec calls with parameterized subprocess arguments |
| `LH-REM-009` | `MEDIUM` | Cleartext Transport & API Policy Upgrade — upgrades insecure http:// URLs to https:// across manifests |
| `LH-REM-010` | `LOW` | Operational Resilience Patch — injects missing HEALTHCHECK instruction into Dockerfile |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-auto-remediation.git
cd lh-auto-remediation

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-remediate` (also accessible via `lh-remediate`, `lh-auto-remediation`).

```bash
# Generate patch preview from finding report and target file
lh-remediate scan findings.json --target Dockerfile

# Apply remediation patches in-place
lh-remediate scan findings.sarif --target deployment.yaml --apply

# Export unified diff to patch file
lh-remediate scan findings.json --target main.tf --output fix.patch

# Display all built-in remediation rules
lh-remediate rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
