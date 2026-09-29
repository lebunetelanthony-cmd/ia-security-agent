#!/usr/bin/env python3

from __future__ import annotations

import argparse
import grp
import json
import os
import platform
import pwd
import re
import secrets
import shutil
import sys
import uuid

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RESULT_SCHEMA = "ia-security-agent-stage-result-v1"

INSTANCE_SCHEMA = "ia-security-agent-instance-config-v1"

EXIT_VALID = 0
EXIT_REFUSED = 20

SECURITY_INVARIANTS = [
    "FAIL_CLOSED",
    "APPEND_ONLY",
    "SHA256_VERIFIED",
    "POSITIVE_EVIDENCE_REQUIRED",
    "UNKNOWN_REMAINS_UNKNOWN",
    "NO_RESOLUTION_FROM_ABSENCE",
    "NO_BLIND_RETRY",
    "PRESERVE_FAILURE_EVIDENCE",
    "NO_AUTOMATIC_REMEDIATION",
    "NO_AUTOMATIC_RISK_ACCEPTANCE",
    "NO_AUTOMATIC_DEFERRAL",
]

RUNTIME_DIRS = [
    "baseline",
    "history/raw",
    "history/meta",
    "history/diff",
    "history/impact",
    "state",
    "reports",
    "runs",
    "attempts",
    "failures",
    "commits",
    "locks",
]

DANGEROUS_TARGETS = {
    Path("/"),
    Path("/etc"),
    Path("/usr"),
    Path("/var"),
    Path("/home"),
    Path("/data"),
    Path("/opt"),
    Path("/srv"),
    Path("/run"),
    Path("/tmp"),
}


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def emit(
    *,
    status: str,
    reason_code: str | None,
    details: dict[str, Any],
) -> None:

    result = {
        "schema": RESULT_SCHEMA,
        "stage": "BOOTSTRAP",
        "status": status,
        "reason_code": reason_code,
        "next_stage_authorized": status == "VALID",
        "details": details,
    }

    print(
        json.dumps(
            result,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
    )


def refuse(
    code: str,
    *,
    details: dict[str, Any],
) -> "NoReturn":

    emit(
        status="REFUSED",
        reason_code=code,
        details=details,
    )

    raise SystemExit(EXIT_REFUSED)


def atomic_write_json(
    path: Path,
    obj: dict[str, Any],
    mode: int = 0o640,
) -> None:

    tmp = path.with_name(
        f".{path.name}.tmp-{uuid.uuid4().hex}"
    )

    data = (
        json.dumps(
            obj,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    fd = os.open(
        tmp,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        mode,
    )

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp, path)

    finally:
        if tmp.exists():
            tmp.unlink()


def validate_uuid(value: str) -> str:

    try:
        parsed = uuid.UUID(value)
    except Exception:
        raise ValueError("invalid UUID")

    return str(parsed)


def validate_timezone(value: str) -> str:

    if not value:
        raise ValueError("timezone empty")

    p = Path(value)

    if p.is_absolute() or ".." in p.parts:
        raise ValueError("invalid timezone path")

    candidate = Path("/usr/share/zoneinfo") / p

    if value != "UTC" and not candidate.is_file():
        raise ValueError("timezone not found")

    return value


def validate_user_group(
    user: str,
    group: str,
) -> None:

    try:
        pwd.getpwnam(user)
    except KeyError:
        raise ValueError("service user not found")

    try:
        grp.getgrnam(group)
    except KeyError:
        raise ValueError("service group not found")


def validate_target(
    target: Path,
    package: Path,
) -> None:

    if not target.is_absolute():
        raise ValueError("target root must be absolute")

    target = target.resolve(strict=False)
    package = package.resolve()

    if target in DANGEROUS_TARGETS:
        raise ValueError("dangerous target root refused")

    try:
        target.relative_to(package)
    except ValueError:
        pass
    else:
        raise ValueError(
            "runtime target inside package forbidden"
        )

    if target == package:
        raise ValueError(
            "runtime target equals package forbidden"
        )

    if target.exists():
        raise FileExistsError(
            "target root already exists"
        )

    if not target.parent.is_dir():
        raise ValueError(
            "target parent does not exist"
        )

    if not os.access(
        target.parent,
        os.W_OK | os.X_OK,
    ):
        raise PermissionError(
            "target parent not writable"
        )


def validate_generated_instance(
    root: Path,
    *,
    helper_enabled: bool,
) -> None:

    config_path = (
        root
        / "config"
        / "instance-config-v1.json"
    )

    if not config_path.is_file():
        raise RuntimeError(
            "instance config missing"
        )

    data = json.loads(
        config_path.read_text(
            encoding="utf-8"
        )
    )

    if data.get("schema") != INSTANCE_SCHEMA:
        raise RuntimeError(
            "instance config schema mismatch"
        )

    identity = data.get("identity", {})

    validate_uuid(identity.get("instance_id", ""))
    validate_uuid(
        identity.get("installation_id", "")
    )

    for rel in RUNTIME_DIRS:
        if not (root / rel).is_dir():
            raise RuntimeError(
                f"runtime directory missing: {rel}"
            )

    secret = (
        root
        / "config"
        / "secrets"
        / "helper-hmac.key"
    )

    if helper_enabled:

        if not secret.is_file():
            raise RuntimeError(
                "helper secret missing"
            )

        if (secret.stat().st_mode & 0o777) != 0o600:
            raise RuntimeError(
                "helper secret mode invalid"
            )

    elif secret.exists():
        raise RuntimeError(
            "unexpected helper secret"
        )


def build_instance(
    *,
    package: Path,
    target: Path,
    service_user: str,
    service_group: str,
    python_bin: str,
    timezone_name: str,
    control_manifest_sha256: str,
    hostname: str,
    enable_zabbix: bool,
    enable_nightly_llm: bool,
    enable_privileged_helper: bool,
) -> None:

    try:
        validate_target(target, package)

    except FileExistsError:
        refuse(
            "DPL1.BOOTSTRAP.TARGET_ALREADY_EXISTS",
            details={
                "target_root": str(target),
                "mutation": "NONE",
            },
        )

    except PermissionError as exc:
        refuse(
            "DPL1.BOOTSTRAP.PERMISSION_INCOMPATIBLE",
            details={
                "target_root": str(target),
                "error": str(exc),
                "mutation": "NONE",
            },
        )

    except ValueError as exc:
        refuse(
            "DPL1.BOOTSTRAP.CONFIG_INVALID",
            details={
                "target_root": str(target),
                "error": str(exc),
                "mutation": "NONE",
            },
        )

    if not re.fullmatch(
        r"[0-9a-f]{64}",
        control_manifest_sha256,
    ):
        refuse(
            "DPL1.BOOTSTRAP.CONFIG_INVALID",
            details={
                "error": "invalid control manifest SHA256",
                "mutation": "NONE",
            },
        )

    python_path = Path(python_bin)

    if (
        not python_path.is_absolute()
        or not python_path.is_file()
        or not os.access(python_path, os.X_OK)
    ):
        refuse(
            "DPL1.BOOTSTRAP.CONFIG_INVALID",
            details={
                "error": "invalid python binary",
                "python_bin": python_bin,
                "mutation": "NONE",
            },
        )

    try:
        validate_user_group(
            service_user,
            service_group,
        )

        timezone_name = validate_timezone(
            timezone_name
        )

    except ValueError as exc:
        refuse(
            "DPL1.BOOTSTRAP.CONFIG_INVALID",
            details={
                "error": str(exc),
                "mutation": "NONE",
            },
        )

    if not hostname:
        refuse(
            "DPL1.BOOTSTRAP.INSTANCE_IDENTITY_FAILED",
            details={
                "error": "hostname empty",
                "mutation": "NONE",
            },
        )

    attempt_id = (
        datetime.now(timezone.utc)
        .strftime("%Y%m%dT%H%M%S%fZ")
        + "-"
        + secrets.token_hex(4)
    )

    instance_id = str(uuid.uuid4())
    installation_id = str(uuid.uuid4())
    created_at = utc_now()

    stage = target.parent / (
        f".{target.name}.bootstrap-{attempt_id}"
    )

    failure = target.parent / (
        f".{target.name}.bootstrap-failure-{attempt_id}"
    )

    if stage.exists() or failure.exists():
        refuse(
            "DPL1.BOOTSTRAP.TRANSACTION_COLLISION",
            details={
                "attempt_id": attempt_id,
                "mutation": "NONE",
            },
        )

    try:

        stage.mkdir(mode=0o750)

        config_dir = stage / "config"
        config_dir.mkdir(mode=0o750)

        for rel in RUNTIME_DIRS:
            (stage / rel).mkdir(
                parents=True,
                exist_ok=False,
                mode=0o750,
            )

        if enable_privileged_helper:

            secret_dir = (
                config_dir / "secrets"
            )

            secret_dir.mkdir(
                mode=0o700
            )

            secret_path = (
                secret_dir
                / "helper-hmac.key"
            )

            fd = os.open(
                secret_path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL,
                0o600,
            )

            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(
                        secrets.token_bytes(32)
                    )
                    f.flush()
                    os.fsync(f.fileno())

            finally:
                os.chmod(
                    secret_path,
                    0o600,
                )

        config = {
            "schema": INSTANCE_SCHEMA,

            "identity": {
                "hostname": hostname,
                "instance_id": instance_id,
                "installation_id": installation_id,
                "created_at": created_at,
            },

            "deployment": {
                "deployment_version": "1",
                "control_manifest_sha256":
                    control_manifest_sha256,
            },

            "filesystem": {
                "runtime_root": str(target),
            },

            "service": {
                "user": service_user,
                "group": service_group,
                "python_bin": python_bin,
            },

            "locale": {
                "timezone": timezone_name,
            },

            "collectors": {
                "core": [],
                "optional": [],
            },

            "integrations": {
                "zabbix": {
                    "enabled": enable_zabbix
                }
            },

            "nightly_llm": {
                "enabled":
                    enable_nightly_llm
            },

            "privileged_helper": {
                "enabled":
                    enable_privileged_helper
            },

            "security_invariants":
                SECURITY_INVARIANTS,
        }

        atomic_write_json(
            config_dir
            / "instance-config-v1.json",
            config,
            0o640,
        )

        validate_generated_instance(
            stage,
            helper_enabled=
                enable_privileged_helper,
        )

        os.rename(stage, target)

        validate_generated_instance(
            target,
            helper_enabled=
                enable_privileged_helper,
        )

    except Exception as exc:

        evidence_path = None

        if stage.exists():

            refusal_obj = {
                "schema":
                    RESULT_SCHEMA,
                "stage":
                    "BOOTSTRAP",
                "status":
                    "REFUSED",
                "reason_code":
                    "DPL1.BOOTSTRAP.TRANSACTION_FAILED",
                "attempt_id":
                    attempt_id,
                "timestamp":
                    utc_now(),
                "error_type":
                    type(exc).__name__,
                "same_attempt_retry_allowed":
                    False,
            }

            try:
                atomic_write_json(
                    stage / "REFUSED.json",
                    refusal_obj,
                    0o640,
                )

                os.rename(
                    stage,
                    failure,
                )

                evidence_path = str(
                    failure
                )

            except Exception:
                evidence_path = str(
                    stage
                )

        refuse(
            "DPL1.BOOTSTRAP.TRANSACTION_FAILED",
            details={
                "attempt_id": attempt_id,
                "error_type":
                    type(exc).__name__,
                "failure_evidence":
                    evidence_path,
            },
        )

    emit(
        status="VALID",
        reason_code=None,
        details={
            "attempt_id": attempt_id,
            "target_root": str(target),
            "hostname": hostname,
            "instance_id": instance_id,
            "installation_id":
                installation_id,
            "created_at": created_at,
            "instance_config":
                str(
                    target
                    / "config"
                    / "instance-config-v1.json"
                ),
            "privileged_helper_enabled":
                enable_privileged_helper,
            "next_stage":
                "INITIAL_VALIDATION",
        },
    )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "IA Security Agent Deployment V1 "
            "transactional instance bootstrap"
        )
    )

    parser.add_argument(
        "--package-root",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--target-root",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--service-user",
        required=True,
    )

    parser.add_argument(
        "--service-group",
        required=True,
    )

    parser.add_argument(
        "--python-bin",
        default=sys.executable,
    )

    parser.add_argument(
        "--timezone",
        default="UTC",
    )

    parser.add_argument(
        "--control-manifest-sha256",
        required=True,
    )

    parser.add_argument(
        "--hostname",
        default=platform.node(),
    )

    parser.add_argument(
        "--enable-zabbix",
        action="store_true",
    )

    parser.add_argument(
        "--enable-nightly-llm",
        action="store_true",
    )

    parser.add_argument(
        "--enable-privileged-helper",
        action="store_true",
    )

    args = parser.parse_args()

    package = (
        args.package_root
        .resolve()
    )

    target = (
        args.target_root
        .resolve(strict=False)
    )

    if not package.is_dir():
        refuse(
            "DPL1.BOOTSTRAP.CONFIG_INVALID",
            details={
                "error": "package root missing",
                "mutation": "NONE",
            },
        )

    build_instance(
        package=package,
        target=target,
        service_user=args.service_user,
        service_group=args.service_group,
        python_bin=args.python_bin,
        timezone_name=args.timezone,
        control_manifest_sha256=
            args.control_manifest_sha256,
        hostname=args.hostname,
        enable_zabbix=args.enable_zabbix,
        enable_nightly_llm=
            args.enable_nightly_llm,
        enable_privileged_helper=
            args.enable_privileged_helper,
    )

    return EXIT_VALID


if __name__ == "__main__":
    raise SystemExit(main())
