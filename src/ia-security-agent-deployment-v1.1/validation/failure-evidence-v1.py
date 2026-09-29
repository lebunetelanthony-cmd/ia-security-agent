#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import uuid

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RESULT_SCHEMA = "ia-security-agent-stage-result-v1"
INSTANCE_SCHEMA = "ia-security-agent-instance-config-v1"
REFUSAL_SCHEMA = "ia-security-agent-refusal-evidence-v1"

EXIT_VALID = 0
EXIT_REFUSED = 20

ATTEMPT_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)

STAGE_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
)

REASON_RE = re.compile(
    r"^DPL1\.[A-Z0-9_.-]+$"
)


def utc_now() -> str:

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def sha256_file(path: Path) -> str:

    h = hashlib.sha256()

    with path.open("rb") as f:
        for block in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(block)

    return h.hexdigest()


def emit(
    *,
    stage: str,
    status: str,
    reason_code: str | None,
    details: dict[str, Any],
) -> None:

    print(
        json.dumps(
            {
                "schema": RESULT_SCHEMA,
                "stage": stage,
                "status": status,
                "reason_code": reason_code,
                "next_stage_authorized":
                    status == "VALID",
                "details": details,
            },
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
    )


def refuse(
    code: str,
    details: dict[str, Any],
) -> "NoReturn":

    emit(
        stage="FAILURE_CONTROL",
        status="REFUSED",
        reason_code=code,
        details=details,
    )

    raise SystemExit(EXIT_REFUSED)


def atomic_json(
    path: Path,
    obj: dict[str, Any],
    mode: int = 0o640,
) -> None:

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
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL,
        mode,
    )

    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def load_instance(
    config_path: Path,
) -> tuple[dict[str, Any], Path]:

    config_path = config_path.resolve()

    if not config_path.is_file():
        refuse(
            "DPL1.FAILURE.INSTANCE_CONFIG_MISSING",
            {
                "path": str(config_path),
            },
        )

    try:
        data = json.loads(
            config_path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        refuse(
            "DPL1.FAILURE.INSTANCE_CONFIG_INVALID",
            {
                "error": type(exc).__name__,
            },
        )

    if (
        not isinstance(data, dict)
        or data.get("schema")
        != INSTANCE_SCHEMA
    ):
        refuse(
            "DPL1.FAILURE.INSTANCE_CONFIG_INVALID",
            {
                "error":
                    "instance schema mismatch",
            },
        )

    runtime_value = (
        data
        .get("filesystem", {})
        .get("runtime_root")
    )

    if not isinstance(
        runtime_value,
        str,
    ):
        refuse(
            "DPL1.FAILURE.INSTANCE_CONFIG_INVALID",
            {
                "error":
                    "runtime_root missing",
            },
        )

    runtime = Path(
        runtime_value
    ).resolve()

    expected = (
        runtime
        / "config"
        / "instance-config-v1.json"
    ).resolve()

    if expected != config_path:
        refuse(
            "DPL1.FAILURE.INSTANCE_CONFIG_INVALID",
            {
                "error":
                    "config/runtime binding mismatch",
            },
        )

    return data, runtime


def validate_identity(
    stage: str,
    attempt_id: str,
) -> None:

    if not STAGE_RE.fullmatch(stage):
        refuse(
            "DPL1.FAILURE.STAGE_INVALID",
            {
                "stage": stage,
            },
        )

    if not ATTEMPT_RE.fullmatch(
        attempt_id
    ):
        refuse(
            "DPL1.FAILURE.ATTEMPT_ID_INVALID",
            {
                "attempt_id":
                    attempt_id,
            },
        )


def parse_details(
    value: str,
) -> dict[str, Any]:

    try:
        obj = json.loads(value)
    except Exception as exc:
        refuse(
            "DPL1.FAILURE.DETAILS_INVALID",
            {
                "error":
                    type(exc).__name__,
            },
        )

    if not isinstance(obj, dict):
        refuse(
            "DPL1.FAILURE.DETAILS_INVALID",
            {
                "error":
                    "details must be object",
            },
        )

    return obj


def evidence_dir(
    runtime: Path,
    stage: str,
    attempt_id: str,
) -> Path:

    return (
        runtime
        / "failures"
        / stage
        / attempt_id
    )


def record_failure(
    *,
    runtime: Path,
    stage: str,
    attempt_id: str,
    reason_code: str,
    details: dict[str, Any],
) -> None:

    validate_identity(
        stage,
        attempt_id,
    )

    if not REASON_RE.fullmatch(
        reason_code
    ):
        refuse(
            "DPL1.FAILURE.REASON_CODE_INVALID",
            {
                "reason_code":
                    reason_code,
            },
        )

    final = evidence_dir(
        runtime,
        stage,
        attempt_id,
    )

    if final.exists():
        refuse(
            "DPL1.FAILURE.EVIDENCE_ALREADY_EXISTS",
            {
                "evidence":
                    str(final),
                "mutation":
                    "NONE",
                "same_attempt_retry_allowed":
                    False,
            },
        )

    parent = final.parent

    parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o750,
    )

    staging = parent / (
        "."
        + attempt_id
        + ".evidence-"
        + uuid.uuid4().hex
    )

    staging.mkdir(
        mode=0o750,
    )

    refusal = {
        "schema":
            REFUSAL_SCHEMA,

        "stage":
            stage,

        "status":
            "REFUSED",

        "reason_code":
            reason_code,

        "attempt_id":
            attempt_id,

        "timestamp":
            utc_now(),

        "same_attempt_retry_allowed":
            False,

        "append_only":
            True,

        "details":
            details,
    }

    try:

        atomic_json(
            staging / "REFUSED.json",
            refusal,
        )

        os.rename(
            staging,
            final,
        )

    except Exception as exc:

        refuse(
            "DPL1.FAILURE.EVIDENCE_MATERIALIZATION_FAILED",
            {
                "error":
                    type(exc).__name__,
                "staging":
                    str(staging),
            },
        )

    refused_file = (
        final / "REFUSED.json"
    )

    emit(
        stage="FAILURE_EVIDENCE",
        status="VALID",
        reason_code=None,
        details={
            "evidence":
                str(refused_file),

            "evidence_sha256":
                sha256_file(
                    refused_file
                ),

            "append_only":
                True,

            "same_attempt_retry_allowed":
                False,
        },
    )


def safe_workspace(
    runtime: Path,
    workspace_value: Path,
) -> tuple[Path, Path]:

    attempts_root = (
        runtime / "attempts"
    ).resolve()

    raw_workspace = workspace_value

    if raw_workspace.is_symlink():
        refuse(
            "DPL1.ROLLBACK.SYMLINK_WORKSPACE_REFUSED",
            {
                "workspace":
                    str(raw_workspace),
            },
        )

    workspace = raw_workspace.resolve()

    if workspace == attempts_root:
        refuse(
            "DPL1.ROLLBACK.WORKSPACE_SCOPE_INVALID",
            {
                "workspace":
                    str(workspace),
            },
        )

    try:
        workspace.relative_to(
            attempts_root
        )
    except ValueError:
        refuse(
            "DPL1.ROLLBACK.WORKSPACE_OUTSIDE_ATTEMPTS",
            {
                "workspace":
                    str(workspace),
                "allowed_root":
                    str(attempts_root),
            },
        )

    if not workspace.is_dir():
        refuse(
            "DPL1.ROLLBACK.WORKSPACE_MISSING",
            {
                "workspace":
                    str(workspace),
            },
        )

    for path in workspace.rglob("*"):

        if path.is_symlink():
            refuse(
                "DPL1.ROLLBACK.SYMLINK_FOUND",
                {
                    "path":
                        str(path),
                },
            )

    return attempts_root, workspace


def inventory_workspace(
    workspace: Path,
) -> list[dict[str, Any]]:

    entries: list[
        dict[str, Any]
    ] = []

    for path in sorted(
        workspace.rglob("*"),
        key=lambda p: str(p),
    ):

        rel = str(
            path.relative_to(
                workspace
            )
        )

        if path.is_dir():

            entries.append(
                {
                    "path": rel,
                    "type": "directory",
                }
            )

        elif path.is_file():

            entries.append(
                {
                    "path": rel,
                    "type": "file",
                    "size":
                        path.stat().st_size,
                    "sha256":
                        sha256_file(path),
                }
            )

        else:

            refuse(
                "DPL1.ROLLBACK.UNKNOWN_OBJECT_TYPE",
                {
                    "path":
                        str(path),
                },
            )

    return entries


def rollback_uncommitted(
    *,
    runtime: Path,
    stage: str,
    attempt_id: str,
    workspace_value: Path,
) -> None:

    validate_identity(
        stage,
        attempt_id,
    )

    _, workspace = safe_workspace(
        runtime,
        workspace_value,
    )

    evidence = evidence_dir(
        runtime,
        stage,
        attempt_id,
    )

    refusal_path = (
        evidence / "REFUSED.json"
    )

    if not refusal_path.is_file():
        refuse(
            "DPL1.ROLLBACK.MATERIALIZED_REFUSAL_REQUIRED",
            {
                "expected":
                    str(refusal_path),
            },
        )

    try:
        refusal = json.loads(
            refusal_path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        refuse(
            "DPL1.ROLLBACK.REFUSAL_EVIDENCE_INVALID",
            {
                "error":
                    type(exc).__name__,
            },
        )

    if (
        not isinstance(refusal, dict)
        or refusal.get("status")
        != "REFUSED"
        or refusal.get("attempt_id")
        != attempt_id
        or refusal.get("stage")
        != stage
    ):
        refuse(
            "DPL1.ROLLBACK.REFUSAL_EVIDENCE_INVALID",
            {
                "evidence":
                    str(refusal_path),
            },
        )

    plan_path = (
        evidence
        / "ROLLBACK-PLAN-v1.json"
    )

    result_path = (
        evidence
        / "ROLLBACK-RESULT-v1.json"
    )

    failure_path = (
        evidence
        / "ROLLBACK-FAILED-v1.json"
    )

    if (
        plan_path.exists()
        or result_path.exists()
        or failure_path.exists()
    ):
        refuse(
            "DPL1.ROLLBACK.ALREADY_MATERIALIZED",
            {
                "evidence":
                    str(evidence),
                "mutation":
                    "NONE",
            },
        )

    refusal_sha_before = (
        sha256_file(
            refusal_path
        )
    )

    inventory = (
        inventory_workspace(
            workspace
        )
    )

    atomic_json(
        plan_path,
        {
            "schema":
                "ia-security-agent-rollback-plan-v1",

            "stage":
                stage,

            "attempt_id":
                attempt_id,

            "timestamp":
                utc_now(),

            "workspace":
                str(workspace),

            "workspace_scope":
                "UNCOMMITTED_ATTEMPTS_SUBTREE",

            "refusal_evidence":
                str(refusal_path),

            "refusal_sha256":
                refusal_sha_before,

            "entries":
                inventory,
        },
    )

    try:

        shutil.rmtree(
            workspace
        )

    except Exception as exc:

        atomic_json(
            failure_path,
            {
                "schema":
                    "ia-security-agent-rollback-failure-v1",

                "stage":
                    stage,

                "attempt_id":
                    attempt_id,

                "timestamp":
                    utc_now(),

                "status":
                    "REFUSED",

                "reason_code":
                    "DPL1.ROLLBACK.REMOVAL_FAILED",

                "error_type":
                    type(exc).__name__,

                "workspace":
                    str(workspace),

                "refusal_sha256":
                    refusal_sha_before,
            },
        )

        refuse(
            "DPL1.ROLLBACK.REMOVAL_FAILED",
            {
                "failure_evidence":
                    str(failure_path),
            },
        )

    refusal_sha_after = (
        sha256_file(
            refusal_path
        )
    )

    if (
        refusal_sha_after
        != refusal_sha_before
    ):

        refuse(
            "DPL1.ROLLBACK.FAILURE_EVIDENCE_MUTATED",
            {
                "before":
                    refusal_sha_before,

                "after":
                    refusal_sha_after,
            },
        )

    atomic_json(
        result_path,
        {
            "schema":
                "ia-security-agent-rollback-result-v1",

            "stage":
                stage,

            "attempt_id":
                attempt_id,

            "timestamp":
                utc_now(),

            "status":
                "VALID",

            "workspace_removed":
                str(workspace),

            "committed_runtime_modified":
                False,

            "failure_evidence_preserved":
                True,

            "refusal_sha256":
                refusal_sha_after,
        },
    )

    emit(
        stage="ROLLBACK",
        status="VALID",
        reason_code=None,
        details={
            "workspace_removed":
                str(workspace),

            "failure_evidence":
                str(refusal_path),

            "refusal_sha256":
                refusal_sha_after,

            "committed_runtime_modified":
                False,

            "failure_evidence_preserved":
                True,
        },
    )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "IA Security Agent Deployment V1 "
            "failure evidence and limited rollback"
        )
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    record = sub.add_parser(
        "record"
    )

    record.add_argument(
        "--instance-config",
        type=Path,
        required=True,
    )

    record.add_argument(
        "--stage",
        required=True,
    )

    record.add_argument(
        "--attempt-id",
        required=True,
    )

    record.add_argument(
        "--reason-code",
        required=True,
    )

    record.add_argument(
        "--details-json",
        default="{}",
    )

    rollback = sub.add_parser(
        "rollback-uncommitted"
    )

    rollback.add_argument(
        "--instance-config",
        type=Path,
        required=True,
    )

    rollback.add_argument(
        "--stage",
        required=True,
    )

    rollback.add_argument(
        "--attempt-id",
        required=True,
    )

    rollback.add_argument(
        "--workspace",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    _, runtime = load_instance(
        args.instance_config
    )

    if args.command == "record":

        details = parse_details(
            args.details_json
        )

        record_failure(
            runtime=runtime,
            stage=args.stage,
            attempt_id=args.attempt_id,
            reason_code=args.reason_code,
            details=details,
        )

        return EXIT_VALID

    if args.command == "rollback-uncommitted":

        rollback_uncommitted(
            runtime=runtime,
            stage=args.stage,
            attempt_id=args.attempt_id,
            workspace_value=args.workspace,
        )

        return EXIT_VALID

    refuse(
        "DPL1.FAILURE.UNKNOWN_COMMAND",
        {
            "command":
                args.command,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
