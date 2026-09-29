#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import sys
from pathlib import Path
from typing import Any


SCHEMA = "ia-security-agent-stage-result-v1"
MANIFEST_SCHEMA = "ia-security-agent-deployment-manifest-v1"

EXIT_VALID = 0
EXIT_REFUSED = 20

REQUIRED_BUILD_DIRS = {
    "bin",
    "lib",
    "collectors",
    "collectors/core",
    "collectors/optional",
    "schemas",
    "contracts",
    "policies",
    "registries",
    "systemd",
    "bootstrap",
    "validation",
    "integrations",
    "integrations/zabbix",
    "nightly-llm",
    "docs",
    "tests",
}

FORBIDDEN_RUNTIME_PARTS = {
    "baseline",
    "history",
    "state",
    "reports",
    "raw",
    "meta",
    "diff",
    "impact",
    "runs",
    "attempts",
    "failures",
    "locks",
    "tmp",
    "staging",
}

FORBIDDEN_SECRET_NAMES = {
    "helper-hmac.key",
    ".webui_secret_key",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)

    return h.hexdigest()


def emit(
    *,
    stage: str,
    status: str,
    reason_code: str | None = None,
    details: dict[str, Any] | None = None,
    checks: list[dict[str, Any]] | None = None,
) -> None:

    obj: dict[str, Any] = {
        "schema": SCHEMA,
        "stage": stage,
        "status": status,
        "reason_code": reason_code,
        "next_stage_authorized": status == "VALID",
        "details": details or {},
        "checks": checks or [],
    }

    print(
        json.dumps(
            obj,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
    )


def refuse(
    stage: str,
    code: str,
    *,
    details: dict[str, Any] | None = None,
    checks: list[dict[str, Any]] | None = None,
) -> "NoReturn":

    emit(
        stage=stage,
        status="REFUSED",
        reason_code=code,
        details=details,
        checks=checks,
    )

    raise SystemExit(EXIT_REFUSED)


def safe_relative_path(value: str) -> Path:

    p = Path(value)

    if p.is_absolute():
        raise ValueError("absolute path forbidden")

    if not p.parts:
        raise ValueError("empty path")

    if ".." in p.parts:
        raise ValueError("parent traversal forbidden")

    return p


def parse_os_release() -> dict[str, str]:

    result: dict[str, str] = {}

    path = Path("/etc/os-release")

    if not path.is_file():
        return result

    for raw in path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():

        raw = raw.strip()

        if (
            not raw
            or raw.startswith("#")
            or "=" not in raw
        ):
            continue

        key, value = raw.split("=", 1)

        value = value.strip().strip('"').strip("'")

        result[key] = value

    return result


def validate_tree(package: Path) -> list[dict[str, Any]]:

    checks: list[dict[str, Any]] = []

    if not package.is_dir():
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.ROOT_MISSING",
            details={"package_root": str(package)},
        )

    present_dirs = {
        str(p.relative_to(package))
        for p in package.rglob("*")
        if p.is_dir()
    }

    missing = sorted(
        REQUIRED_BUILD_DIRS - present_dirs
    )

    if missing:
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.REQUIRED_DIRECTORY_MISSING",
            details={"missing": missing},
        )

    forbidden = []

    for p in package.rglob("*"):

        rel = p.relative_to(package)

        if any(
            part in FORBIDDEN_RUNTIME_PARTS
            for part in rel.parts
        ):
            forbidden.append(str(rel))

    if forbidden:
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.FORBIDDEN_RUNTIME_FOUND",
            details={
                "paths": sorted(set(forbidden))
            },
        )

    secret_paths = []

    for p in package.rglob("*"):

        if not p.is_file():
            continue

        if p.name in FORBIDDEN_SECRET_NAMES:
            secret_paths.append(
                str(p.relative_to(package))
            )

    if secret_paths:
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.SECRET_MATERIAL_FOUND",
            details={"paths": sorted(secret_paths)},
        )

    checks.append(
        {
            "check_id": "package.tree",
            "status": "VALID",
            "evidence": (
                f"{len(REQUIRED_BUILD_DIRS)} "
                "required directories present"
            ),
        }
    )

    return checks


def self_test(package: Path) -> None:

    checks = validate_tree(package)

    script = Path(__file__).resolve()

    if not script.is_file():
        refuse(
            "D5_SELF_TEST",
            "DPL1.INTERNAL.PREFLIGHT_SELF_MISSING",
        )

    wrapper = (
        package
        / "bin"
        / "preflight-ia-security-agent"
    )

    if not wrapper.is_file():
        refuse(
            "D5_SELF_TEST",
            "DPL1.INTERNAL.PREFLIGHT_WRAPPER_MISSING",
        )

    checks.extend(
        [
            {
                "check_id": "preflight.engine",
                "status": "VALID",
                "evidence": str(script),
            },
            {
                "check_id": "preflight.engine.sha256",
                "status": "VALID",
                "evidence": sha256_file(script),
            },
            {
                "check_id": "preflight.wrapper",
                "status": "VALID",
                "evidence": str(wrapper),
            },
            {
                "check_id": "runtime.mutation",
                "status": "VALID",
                "evidence": "NONE",
            },
        ]
    )

    emit(
        stage="D5_SELF_TEST",
        status="VALID",
        details={
            "mode": "READ_ONLY_VALIDATION",
            "package_root": str(package),
        },
        checks=checks,
    )


def load_manifest(package: Path) -> tuple[Path, dict[str, Any]]:

    manifest_path = (
        package / "DEPLOYMENT-MANIFEST.json"
    )

    if not manifest_path.is_file():
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.REQUIRED_FILE_MISSING",
            details={
                "missing": "DEPLOYMENT-MANIFEST.json"
            },
        )

    try:
        data = json.loads(
            manifest_path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.MANIFEST_INVALID",
            details={
                "error": type(exc).__name__
            },
        )

    if not isinstance(data, dict):
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.MANIFEST_INVALID",
            details={"error": "root_not_object"},
        )

    if data.get("schema") != MANIFEST_SCHEMA:
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.MANIFEST_INVALID",
            details={
                "error": "schema_mismatch",
                "observed": data.get("schema"),
            },
        )

    if data.get("runtime_content_allowed") is not False:
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.MANIFEST_INVALID",
            details={
                "error": (
                    "runtime_content_allowed_must_be_false"
                )
            },
        )

    files = data.get("files")

    if not isinstance(files, list) or not files:
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.MANIFEST_INVALID",
            details={"error": "files_missing_or_empty"},
        )

    return manifest_path, data


def validate_manifest_files(
    package: Path,
    manifest: dict[str, Any],
) -> list[dict[str, Any]]:

    checks: list[dict[str, Any]] = []

    seen: set[str] = set()

    for entry in manifest["files"]:

        if not isinstance(entry, dict):
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.MANIFEST_INVALID",
                details={"error": "file_entry_not_object"},
            )

        path_value = entry.get("path")
        expected_sha = entry.get("sha256")

        if not isinstance(path_value, str):
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.MANIFEST_INVALID",
                details={"error": "invalid_file_path"},
            )

        try:
            rel = safe_relative_path(path_value)
        except ValueError as exc:
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.MANIFEST_INVALID",
                details={
                    "file": path_value,
                    "error": str(exc),
                },
            )

        rel_string = str(rel)

        if rel_string in seen:
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.MANIFEST_INVALID",
                details={
                    "error": "duplicate_file",
                    "file": rel_string,
                },
            )

        seen.add(rel_string)

        if any(
            part in FORBIDDEN_RUNTIME_PARTS
            for part in rel.parts
        ):
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.FORBIDDEN_RUNTIME_FOUND",
                details={"file": rel_string},
            )

        target = package / rel

        if not target.is_file():
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.REQUIRED_FILE_MISSING",
                details={"missing": rel_string},
            )

        if not isinstance(expected_sha, str) or not re.fullmatch(
            r"[0-9a-f]{64}",
            expected_sha,
        ):
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.MANIFEST_INVALID",
                details={
                    "file": rel_string,
                    "error": "invalid_sha256",
                },
            )

        observed = sha256_file(target)

        if observed != expected_sha:
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.CHECKSUM_MISMATCH",
                details={
                    "file": rel_string,
                    "expected": expected_sha,
                    "observed": observed,
                },
            )

    actual_files = {
        str(candidate.relative_to(package))
        for candidate in package.rglob("*")
        if candidate.is_file()
        and str(candidate.relative_to(package))
        != "DEPLOYMENT-MANIFEST.json"
    }

    unmanifested = sorted(
        actual_files - seen
    )

    if unmanifested:
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.UNMANIFESTED_FILE_FOUND",
            details={
                "files": unmanifested,
            },
        )

    checks.append(
        {
            "check_id": "manifest.files.sha256",
            "status": "VALID",
            "evidence": f"{len(seen)} files",
        }
    )

    return checks


def validate_control_sums(
    package: Path,
) -> list[dict[str, Any]]:

    sums_path = package / "CONTROL-SHA256SUMS"

    if not sums_path.is_file():
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.REQUIRED_FILE_MISSING",
            details={
                "missing": "CONTROL-SHA256SUMS"
            },
        )

    count = 0

    for lineno, raw in enumerate(
        sums_path.read_text(
            encoding="utf-8",
            errors="strict",
        ).splitlines(),
        1,
    ):

        line = raw.strip()

        if not line:
            continue

        match = re.fullmatch(
            r"([0-9a-f]{64})  (.+)",
            line,
        )

        if not match:
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.MANIFEST_INVALID",
                details={
                    "file": "CONTROL-SHA256SUMS",
                    "line": lineno,
                    "error": "invalid_checksum_format",
                },
            )

        expected, relative = match.groups()

        try:
            rel = safe_relative_path(relative)
        except ValueError as exc:
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.MANIFEST_INVALID",
                details={
                    "file": "CONTROL-SHA256SUMS",
                    "line": lineno,
                    "error": str(exc),
                },
            )

        target = package / rel

        if not target.is_file():
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.REQUIRED_FILE_MISSING",
                details={"missing": str(rel)},
            )

        observed = sha256_file(target)

        if observed != expected:
            refuse(
                "PACKAGE",
                "DPL1.PACKAGE.CHECKSUM_MISMATCH",
                details={
                    "file": str(rel),
                    "expected": expected,
                    "observed": observed,
                },
            )

        count += 1

    if count == 0:
        refuse(
            "PACKAGE",
            "DPL1.PACKAGE.MANIFEST_INVALID",
            details={
                "error": "empty_CONTROL-SHA256SUMS"
            },
        )

    return [
        {
            "check_id": "control.sha256",
            "status": "VALID",
            "evidence": f"{count} entries",
        }
    ]


def validate_host() -> list[dict[str, Any]]:

    checks: list[dict[str, Any]] = []

    mandatory = [
        "python3",
        "systemctl",
        "sha256sum",
    ]

    missing = [
        command
        for command in mandatory
        if shutil.which(command) is None
    ]

    if missing:
        refuse(
            "HOST",
            "DPL1.HOST.DEPENDENCY_MISSING",
            details={"missing": missing},
        )

    if platform.system() != "Linux":
        refuse(
            "HOST",
            "DPL1.HOST.OS_UNSUPPORTED",
            details={
                "observed": platform.system()
            },
        )

    if sys.version_info < (3, 10):
        refuse(
            "HOST",
            "DPL1.HOST.PYTHON_VERSION_UNSUPPORTED",
            details={
                "observed": (
                    f"{sys.version_info.major}."
                    f"{sys.version_info.minor}."
                    f"{sys.version_info.micro}"
                ),
                "required": ">=3.10",
            },
        )

    checks.append(
        {
            "check_id": "host.python",
            "status": "VALID",
            "evidence": (
                f"{sys.version_info.major}."
                f"{sys.version_info.minor}."
                f"{sys.version_info.micro}"
            ),
        }
    )

    os_release = parse_os_release()

    checks.extend(
        [
            {
                "check_id": "host.os",
                "status": "VALID",
                "evidence": {
                    "system": platform.system(),
                    "id": os_release.get("ID"),
                    "version_id": os_release.get(
                        "VERSION_ID"
                    ),
                },
            },
            {
                "check_id": "host.arch",
                "status": "VALID",
                "evidence": platform.machine(),
            },
            {
                "check_id": "host.dependencies",
                "status": "VALID",
                "evidence": mandatory,
            },
        ]
    )

    return checks


def production_preflight(package: Path) -> None:

    checks = validate_tree(package)

    _, manifest = load_manifest(package)

    checks.extend(
        validate_manifest_files(
            package,
            manifest,
        )
    )

    checks.extend(
        validate_control_sums(package)
    )

    checks.extend(validate_host())

    emit(
        stage="PREFLIGHT",
        status="VALID",
        details={
            "package_root": str(package),
            "hostname": platform.node(),
            "architecture": platform.machine(),
        },
        checks=checks,
    )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "IA Security Agent Deployment V1 "
            "fail-closed preflight"
        )
    )

    parser.add_argument(
        "--package-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )

    parser.add_argument(
        "--self-test",
        action="store_true",
        help=(
            "Validate the preflight engine and "
            "development package tree without "
            "requiring the final manifest."
        ),
    )

    args = parser.parse_args()

    package = args.package_root.resolve()

    if args.self_test:
        self_test(package)
        return EXIT_VALID

    production_preflight(package)

    return EXIT_VALID


if __name__ == "__main__":
    raise SystemExit(main())
