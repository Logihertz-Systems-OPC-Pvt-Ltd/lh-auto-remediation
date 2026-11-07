# Security Rules Reference: lh-auto-remediation

An enterprise automated security remediation & patch engine developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-auto-remediation`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-REM-001` | `CRITICAL` | Container Hardening | Container Root Execution Fix |
| `LH-REM-002` | `HIGH` | Supply Chain | Unpinned Base Image & Dependency Fix |
| `LH-REM-003` | `CRITICAL` | Secret Hygiene | Hardcoded Secret Externalization |
| `LH-REM-004` | `HIGH` | Workload Hardening | Container & K8s SecurityContext Hardening |
| `LH-REM-005` | `CRITICAL` | IaC Remediation | Cloud Storage & Ingress Lockdown |
| `LH-REM-006` | `HIGH` | System Hardening | Linux Kernel sysctl Hardening Patch |
| `LH-REM-007` | `HIGH` | Database Hardening | Database Binding & Auth Hardening Patch |
| `LH-REM-008` | `HIGH` | Code Remediation | Unsafe Command & Code Sink Replacement |
| `LH-REM-009` | `MEDIUM` | Transport Security | Cleartext Transport & API Policy Upgrade |
| `LH-REM-010` | `LOW` | Resilience | Operational Resilience Patch |

---

## Granular Rule Specifications

### `LH-REM-001`: Container Root Execution Fix

- **Severity**: `CRITICAL`
- **Category**: `Container Hardening`
- **Description**: Detects missing non-root USER instruction or USER 0 root execution in Dockerfile.
- **Remediation**: Injects dedicated non-root user creation and USER nonroot directive into target Dockerfile.

---

### `LH-REM-002`: Unpinned Base Image & Dependency Fix

- **Severity**: `HIGH`
- **Category**: `Supply Chain`
- **Description**: Mutable :latest container tags or unpinned package dependencies subject to supply-chain drift.
- **Remediation**: Pins mutable base image tags to specific SHA-256 digest hashes in Dockerfile.

---

### `LH-REM-003`: Hardcoded Secret Externalization

- **Severity**: `CRITICAL`
- **Category**: `Secret Hygiene`
- **Description**: Plaintext passwords, tokens, or credentials embedded directly in source manifests.
- **Remediation**: Replaces hardcoded credential values with environment variable bindings or secret references.

---

### `LH-REM-004`: Container & K8s SecurityContext Hardening

- **Severity**: `HIGH`
- **Category**: `Workload Hardening`
- **Description**: Kubernetes pod or container spec missing restrictive securityContext guardrails.
- **Remediation**: Injects readOnlyRootFilesystem, drop ALL capabilities, and runAsNonRoot into container spec.

---

### `LH-REM-005`: Cloud Storage & Ingress Lockdown

- **Severity**: `CRITICAL`
- **Category**: `IaC Remediation`
- **Description**: Terraform public S3 buckets or unrestricted 0.0.0.0/0 ingress security group rules.
- **Remediation**: Patches Terraform manifests to enforce private ACLs and restricts ingress CIDR blocks.

---

### `LH-REM-006`: Linux Kernel sysctl Hardening Patch

- **Severity**: `HIGH`
- **Category**: `System Hardening`
- **Description**: Insecure Linux kernel network parameters (ip_forward enabled, syncookies disabled).
- **Remediation**: Generates sysctl configuration patches enforcing CIS benchmark hardened parameters.

---

### `LH-REM-007`: Database Binding & Auth Hardening Patch

- **Severity**: `HIGH`
- **Category**: `Database Hardening`
- **Description**: Wildcard 0.0.0.0 network binds or insecure trust authentication in database configs.
- **Remediation**: Patches database listeners to localhost/internal IPs and upgrades pg_hba.conf to scram-sha-256.

---

### `LH-REM-008`: Unsafe Command & Code Sink Replacement

- **Severity**: `HIGH`
- **Category**: `Code Remediation`
- **Description**: Dangerous shell execution (shell=True, system()) susceptible to command injection.
- **Remediation**: Replaces raw shell execution with parameterized subprocess arguments without shell interpolation.

---

### `LH-REM-009`: Cleartext Transport & API Policy Upgrade

- **Severity**: `MEDIUM`
- **Category**: `Transport Security`
- **Description**: Insecure http:// endpoints declared in API manifests or service definitions.
- **Remediation**: Upgrades cleartext URL references to https:// schemes across configuration files.

---

### `LH-REM-010`: Operational Resilience Patch

- **Severity**: `LOW`
- **Category**: `Resilience`
- **Description**: Container missing HEALTHCHECK instruction for runtime health monitoring.
- **Remediation**: Injects container HEALTHCHECK instruction with interval, timeout, and retries configuration.

---
