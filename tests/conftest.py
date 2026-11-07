# ==============================================================================
# Product:       lh-auto-remediation (lh-remediate)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared pytest fixtures for lh-auto-remediation test suite.

Provides temporary mock project structures, hardened configurations, and insecure files
for validating remediation rules LH-REM-001 through LH-REM-010.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def clean_hardened_project(tmp_path: Path) -> Path:
    """Create a project directory with fully hardened configurations requiring zero patches."""
    proj = tmp_path / "hardened_app"
    proj.mkdir()

    # Hardened Dockerfile
    dockerfile = proj / "Dockerfile"
    dockerfile.write_text(
        "FROM alpine:3.20\n"
        "RUN apk add --no-cache curl\n"
        "COPY app.py /app/app.py\n"
        "RUN addgroup -S appgroup && adduser -S appuser -G appgroup\n"
        "USER appuser\n"
        "HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8080/health\n"
        'CMD ["python", "/app/app.py"]\n',
        encoding="utf-8",
    )
    return proj


@pytest.fixture
def insecure_dockerfile(tmp_path: Path) -> Path:
    """Create an insecure Dockerfile triggering REM-001, REM-002, REM-003, REM-008, REM-010."""
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM ubuntu:latest\n"
        "ENV API_KEY=supersecretkey12345\n"
        "ADD myapp.tar.gz /app/\n"
        "RUN apt-get update && apt-get install -y nginx curl\n"
        "USER root\n"
        'CMD ["nginx", "-g", "daemon off;"]\n',
        encoding="utf-8",
    )
    return df


@pytest.fixture
def insecure_compose_and_k8s(tmp_path: Path) -> Path:
    """Create insecure docker-compose and Kubernetes manifests for REM-003, REM-004, REM-010."""
    proj = tmp_path / "workloads"
    proj.mkdir()

    compose_file = proj / "docker-compose.yml"
    compose_file.write_text(
        "version: '3.8'\n"
        "services:\n"
        "  db:\n"
        "    image: postgres:15\n"
        "    privileged: true\n"
        "    network_mode: host\n"
        "    environment:\n"
        "      POSTGRES_PASSWORD: mysecretpassword123\n",
        encoding="utf-8",
    )

    k8s_file = proj / "deployment.yaml"
    k8s_file.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web-app\n"
        "spec:\n"
        "  replicas: 1\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: web\n"
        "          image: nginx:1.25\n",
        encoding="utf-8",
    )
    return proj


@pytest.fixture
def insecure_terraform_file(tmp_path: Path) -> Path:
    """Create an insecure Terraform HCL file triggering REM-005."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "company-data"\n'
        '  acl    = "public-read"\n'
        "  server_side_encryption_configuration {\n"
        "    rule {\n"
        "      encrypted = false\n"
        "    }\n"
        "  }\n"
        "}\n"
        'resource "aws_security_group" "allow_ssh" {\n'
        "  ingress {\n"
        "    from_port   = 22\n"
        "    to_port     = 22\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    return tf_file


@pytest.fixture
def insecure_kernel_and_db(tmp_path: Path) -> Path:
    """Create insecure sysctl and database configs triggering REM-006 and REM-007."""
    proj = tmp_path / "infra"
    proj.mkdir()

    sysctl_file = proj / "sysctl.conf"
    sysctl_file.write_text(
        "net.ipv4.ip_forward = 1\nnet.ipv4.tcp_syncookies = 0\nkernel.randomize_va_space = 0\n",
        encoding="utf-8",
    )

    pg_file = proj / "postgresql.conf"
    pg_file.write_text(
        "listen_addresses = '*'\nssl = off\n",
        encoding="utf-8",
    )

    hba_file = proj / "pg_hba.conf"
    hba_file.write_text(
        "host all all 0.0.0.0/0 trust\n",
        encoding="utf-8",
    )
    return proj


@pytest.fixture
def insecure_code_and_api(tmp_path: Path) -> Path:
    """Create Python file and OpenAPI spec triggering REM-008 and REM-009."""
    proj = tmp_path / "app"
    proj.mkdir()

    py_file = proj / "loader.py"
    py_file.write_text(
        "import yaml\n\ndef parse_data(payload):\n    return yaml.load(payload)\n",
        encoding="utf-8",
    )

    api_file = proj / "openapi.yaml"
    api_file.write_text(
        "openapi: 3.0.0\n"
        "info:\n"
        "  title: Sample API\n"
        "servers:\n"
        "  - url: http://api.example.com/v1\n",
        encoding="utf-8",
    )
    return proj
