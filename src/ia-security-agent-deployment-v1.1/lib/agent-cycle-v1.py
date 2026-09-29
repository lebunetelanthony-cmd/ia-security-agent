#!/usr/bin/env python3

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import sys
import uuid

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RESULT_SCHEMA = "ia-security-agent-stage-result-v1"
INSTANCE_SCHEMA = "ia-security-agent-instance-config-v1"

OBS_SCHEMA = "ia-security-agent-observation-v1"
DIFF_SCHEMA = "ia-security-agent-diff-v1"
IMPACT_SCHEMA = "ia-security-agent-impact-v1"
REPORT_SCHEMA = "ia-security-agent-incremental-report-v1"
COMMIT_SCHEMA = "ia-security-agent-cycle-commit-v1"
HEAD_SCHEMA = "ia-security-agent-head-v1"

EXIT_VALID = 0
EXIT_REFUSED = 20


def utc_now() -> str:

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def canonical(
    obj: Any,
) -> bytes:

    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(
    value: bytes,
) -> str:

    return hashlib.sha256(
        value
    ).hexdigest()


def sha256_file(
    path: Path,
) -> str:

    h = hashlib.sha256()

    with path.open("rb") as f:

        for block in iter(
            lambda: f.read(
                1024 * 1024
            ),
            b"",
        ):
            h.update(block)

    return h.hexdigest()


def emit(
    *,
    status: str,
    reason_code: str | None,
    details: dict[str, Any],
) -> None:

    print(
        json.dumps(
            {
                "schema":
                    RESULT_SCHEMA,
                "stage":
                    "CORE_CYCLE",
                "status":
                    status,
                "reason_code":
                    reason_code,
                "next_stage_authorized":
                    status == "VALID",
                "details":
                    details,
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
        status="REFUSED",
        reason_code=code,
        details=details,
    )

    raise SystemExit(
        EXIT_REFUSED
    )


def exclusive_json(
    path: Path,
    obj: Any,
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

    with os.fdopen(
        fd,
        "wb",
    ) as f:

        f.write(data)
        f.flush()
        os.fsync(
            f.fileno()
        )


def atomic_replace_json(
    path: Path,
    obj: Any,
) -> None:

    tmp = path.with_name(
        "."
        + path.name
        + ".tmp-"
        + uuid.uuid4().hex
    )

    exclusive_json(
        tmp,
        obj,
    )

    os.replace(
        tmp,
        path,
    )


def load_json(
    path: Path,
    *,
    code: str,
) -> dict[str, Any]:

    if not path.is_file():
        refuse(
            code,
            {
                "error":
                    "file missing",
                "path":
                    str(path),
            },
        )

    try:
        obj = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        refuse(
            code,
            {
                "error":
                    type(exc).__name__,
                "path":
                    str(path),
            },
        )

    if not isinstance(
        obj,
        dict,
    ):
        refuse(
            code,
            {
                "error":
                    "root not object",
                "path":
                    str(path),
            },
        )

    return obj


def load_instance(
    config_path: Path,
    package: Path,
) -> tuple[
    dict[str, Any],
    Path,
]:

    config_path = (
        config_path.resolve()
    )

    instance = load_json(
        config_path,
        code=
            "DPL1.CORE.INSTANCE_CONFIG_INVALID",
    )

    if (
        instance.get("schema")
        != INSTANCE_SCHEMA
    ):
        refuse(
            "DPL1.CORE.INSTANCE_CONFIG_INVALID",
            {
                "error":
                    "schema mismatch",
            },
        )

    runtime_value = (
        instance
        .get("filesystem", {})
        .get("runtime_root")
    )

    if not isinstance(
        runtime_value,
        str,
    ):
        refuse(
            "DPL1.CORE.INSTANCE_CONFIG_INVALID",
            {
                "error":
                    "runtime_root missing",
            },
        )

    runtime = Path(
        runtime_value
    ).resolve()

    expected_config = (
        runtime
        / "config"
        / "instance-config-v1.json"
    ).resolve()

    if expected_config != config_path:
        refuse(
            "DPL1.CORE.INSTANCE_CONFIG_INVALID",
            {
                "error":
                    "runtime/config binding mismatch",
            },
        )

    manifest = (
        package
        / "DEPLOYMENT-MANIFEST.json"
    )

    if not manifest.is_file():
        refuse(
            "DPL1.CORE.CONTROL_MANIFEST_MISSING",
            {
                "manifest":
                    str(manifest),
            },
        )

    expected_sha = (
        instance
        .get("deployment", {})
        .get(
            "control_manifest_sha256"
        )
    )

    observed_sha = (
        sha256_file(
            manifest
        )
    )

    if (
        not isinstance(
            expected_sha,
            str,
        )
        or expected_sha
        != observed_sha
    ):
        refuse(
            "DPL1.CORE.CONTROL_MANIFEST_MISMATCH",
            {
                "expected":
                    expected_sha,
                "observed":
                    observed_sha,
            },
        )

    return (
        instance,
        runtime,
    )


def load_collector(
    path: Path,
):

    if not path.is_file():
        refuse(
            "DPL1.CORE.COLLECTOR_MISSING",
            {
                "collector":
                    str(path),
            },
        )

    spec = (
        importlib.util
        .spec_from_file_location(
            "ia_security_linux_collector",
            path,
        )
    )

    if (
        spec is None
        or spec.loader is None
    ):
        refuse(
            "DPL1.CORE.COLLECTOR_INVALID",
            {
                "collector":
                    str(path),
            },
        )

    module = (
        importlib.util
        .module_from_spec(
            spec
        )
    )

    spec.loader.exec_module(
        module
    )

    if not hasattr(
        module,
        "collect",
    ):
        refuse(
            "DPL1.CORE.COLLECTOR_INVALID",
            {
                "error":
                    "collect() missing",
            },
        )

    return module


def section_hashes(
    payload: dict[str, Any],
) -> dict[str, str]:

    return {
        key:
            sha256_bytes(
                canonical(
                    payload[key]
                )
            )
        for key in sorted(payload)
    }


def package_delta(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:

    def mapping(
        obj: dict[str, Any],
    ) -> dict[tuple[str, str], str]:

        items = (
            obj.get(
                "packages",
                {}
            )
            .get(
                "items",
                [],
            )
        )

        result = {}

        if not isinstance(
            items,
            list,
        ):
            return result

        for item in items:

            if not isinstance(
                item,
                dict,
            ):
                continue

            name = item.get("name")
            arch = item.get(
                "architecture"
            )
            version = item.get(
                "version"
            )

            if all(
                isinstance(x, str)
                for x in (
                    name,
                    arch,
                    version,
                )
            ):
                result[
                    (name, arch)
                ] = version

        return result

    old = mapping(previous)
    new = mapping(current)

    old_keys = set(old)
    new_keys = set(new)

    added = sorted(
        [
            {
                "name": name,
                "architecture": arch,
                "version": new[
                    (name, arch)
                ],
            }
            for name, arch in (
                new_keys - old_keys
            )
        ],
        key=lambda x: (
            x["name"],
            x["architecture"],
        ),
    )

    removed = sorted(
        [
            {
                "name": name,
                "architecture": arch,
                "version": old[
                    (name, arch)
                ],
            }
            for name, arch in (
                old_keys - new_keys
            )
        ],
        key=lambda x: (
            x["name"],
            x["architecture"],
        ),
    )

    changed = []

    for key in sorted(
        old_keys & new_keys
    ):

        if old[key] != new[key]:

            changed.append(
                {
                    "name":
                        key[0],
                    "architecture":
                        key[1],
                    "previous_version":
                        old[key],
                    "current_version":
                        new[key],
                }
            )

    return {
        "added": added,
        "removed": removed,
        "version_changed":
            changed,
    }


def relative_to_runtime(
    path: Path,
    runtime: Path,
) -> str:

    return str(
        path.resolve()
        .relative_to(
            runtime.resolve()
        )
    )


def materialize_failure(
    *,
    runtime: Path,
    run_id: str,
    stage: Path,
    committed_run: Path,
    error: Exception,
) -> str | None:

    root = (
        runtime
        / "failures"
        / "core"
    )

    root.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o750,
    )

    postcommit = (
        committed_run.exists()
    )

    final = (
        root
        / (
            run_id
            + (
                "-postcommit"
                if postcommit
                else ""
            )
        )
    )

    if final.exists():
        return str(final)

    refusal = {
        "schema":
            "ia-security-agent-refusal-evidence-v1",

        "stage":
            "core-cycle",

        "status":
            "REFUSED",

        "reason_code":
            (
                "DPL1.CORE.POST_COMMIT_FAILURE"
                if postcommit
                else
                "DPL1.CORE.CYCLE_FAILED"
            ),

        "attempt_id":
            run_id,

        "timestamp":
            utc_now(),

        "same_attempt_retry_allowed":
            False,

        "append_only":
            True,

        "details": {
            "error_type":
                type(error).__name__,

            "committed_run_preserved":
                postcommit,
        },
    }

    try:

        if stage.exists():

            exclusive_json(
                stage / "REFUSED.json",
                refusal,
            )

            os.rename(
                stage,
                final,
            )

        else:

            final.mkdir(
                mode=0o750,
            )

            exclusive_json(
                final / "REFUSED.json",
                refusal,
            )

        return str(final)

    except Exception:

        return None


def cycle(
    config_path: Path,
) -> None:

    package = (
        Path(__file__)
        .resolve()
        .parents[1]
    )

    instance, runtime = (
        load_instance(
            config_path,
            package,
        )
    )

    unresolved = (
        runtime
        / "failures"
        / "core"
    )

    if unresolved.is_dir():

        postcommit = [
            p
            for p in unresolved.iterdir()
            if (
                p.is_dir()
                and p.name.endswith(
                    "-postcommit"
                )
            )
        ]

        if postcommit:

            refuse(
                "DPL1.CORE.UNRESOLVED_POST_COMMIT_FAILURE",
                {
                    "failures":
                        sorted(
                            str(p)
                            for p in postcommit
                        ),
                },
            )

    lock_path = (
        runtime
        / "locks"
        / "agent-cycle.lock"
    )

    lock_fd = os.open(
        lock_path,
        os.O_RDWR
        | os.O_CREAT,
        0o640,
    )

    try:

        try:
            fcntl.flock(
                lock_fd,
                fcntl.LOCK_EX
                | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            refuse(
                "DPL1.CORE.LOCK_BUSY",
                {
                    "lock":
                        str(lock_path),
                },
            )

        head_path = (
            runtime
            / "state"
            / "HEAD.json"
        )

        previous_head = None
        previous_observation = None

        if head_path.exists():

            previous_head = load_json(
                head_path,
                code=
                    "DPL1.CORE.HEAD_INVALID",
            )

            if (
                previous_head.get(
                    "schema"
                )
                != HEAD_SCHEMA
            ):
                refuse(
                    "DPL1.CORE.HEAD_INVALID",
                    {
                        "error":
                            "schema mismatch",
                    },
                )

            previous_rel = (
                previous_head
                .get(
                    "current",
                    {}
                )
                .get(
                    "observation"
                )
            )

            if not isinstance(
                previous_rel,
                str,
            ):
                refuse(
                    "DPL1.CORE.HEAD_INVALID",
                    {
                        "error":
                            "current observation missing",
                    },
                )

            previous_path = (
                runtime
                / previous_rel
            ).resolve()

            try:
                previous_path.relative_to(
                    runtime.resolve()
                )
            except ValueError:
                refuse(
                    "DPL1.CORE.HEAD_INVALID",
                    {
                        "error":
                            "observation escapes runtime",
                    },
                )

            previous_observation = (
                load_json(
                    previous_path,
                    code=
                        "DPL1.CORE.PREVIOUS_OBSERVATION_INVALID",
                )
            )

        else:

            run_root = (
                runtime
                / "runs"
                / "core"
            )

            if (
                run_root.is_dir()
                and any(
                    p.is_dir()
                    for p in run_root.iterdir()
                )
            ):
                refuse(
                    "DPL1.CORE.ORPHAN_COMMITTED_RUN",
                    {
                        "run_root":
                            str(run_root),
                    },
                )

        collector_path = (
            package
            / "collectors"
            / "core"
            / "linux-host-v1.py"
        )

        collector = (
            load_collector(
                collector_path
            )
        )

        run_id = (
            datetime.now(
                timezone.utc
            )
            .strftime(
                "%Y%m%dT%H%M%S%fZ"
            )
            + "-"
            + secrets.token_hex(4)
        )

        attempts_root = (
            runtime
            / "attempts"
            / "core"
        )

        runs_root = (
            runtime
            / "runs"
            / "core"
        )

        attempts_root.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o750,
        )

        runs_root.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o750,
        )

        stage = (
            attempts_root
            / run_id
        )

        run_target = (
            runs_root
            / run_id
        )

        stage.mkdir(
            mode=0o750
        )

        committed = False

        try:

            collected = (
                collector.collect()
            )

            if (
                not isinstance(
                    collected,
                    dict,
                )
                or not isinstance(
                    collected.get(
                        "payload"
                    ),
                    dict,
                )
            ):
                raise RuntimeError(
                    "collector output invalid"
                )

            payload = (
                collected["payload"]
            )

            payload_sha = (
                sha256_bytes(
                    canonical(payload)
                )
            )

            observation = {
                "schema":
                    OBS_SCHEMA,

                "run_id":
                    run_id,

                "collected_at":
                    utc_now(),

                "instance_id":
                    instance[
                        "identity"
                    ][
                        "instance_id"
                    ],

                "installation_id":
                    instance[
                        "identity"
                    ][
                        "installation_id"
                    ],

                "collector_schema":
                    collected.get(
                        "schema"
                    ),

                "collector_version":
                    collected.get(
                        "collector_version"
                    ),

                "payload_sha256":
                    payload_sha,

                "payload":
                    payload,
            }

            current_sections = (
                section_hashes(
                    payload
                )
            )

            if previous_observation:

                previous_payload = (
                    previous_observation
                    .get(
                        "payload",
                        {}
                    )
                )

                if not isinstance(
                    previous_payload,
                    dict,
                ):
                    raise RuntimeError(
                        "previous payload invalid"
                    )

                previous_sections = (
                    section_hashes(
                        previous_payload
                    )
                )

                all_sections = sorted(
                    set(
                        previous_sections
                    )
                    | set(
                        current_sections
                    )
                )

                changed_sections = [
                    section
                    for section in all_sections
                    if (
                        previous_sections
                        .get(section)
                        != current_sections
                        .get(section)
                    )
                ]

                package_changes = (
                    package_delta(
                        previous_payload,
                        payload,
                    )
                )

                initial_baseline = False

            else:

                previous_sections = {}
                changed_sections = []
                package_changes = {
                    "added": [],
                    "removed": [],
                    "version_changed": [],
                }
                initial_baseline = True

            diff = {
                "schema":
                    DIFF_SCHEMA,

                "run_id":
                    run_id,

                "initial_baseline":
                    initial_baseline,

                "previous_run_id":
                    (
                        previous_head
                        .get("current", {})
                        .get("run_id")
                        if previous_head
                        else None
                    ),

                "previous_section_sha256":
                    previous_sections,

                "current_section_sha256":
                    current_sections,

                "changed_sections":
                    changed_sections,

                "package_changes":
                    package_changes,

                "security_resolution":
                    "NOT_ASSERTED",
            }

            change_detected = bool(
                changed_sections
            )

            impact = {
                "schema":
                    IMPACT_SCHEMA,

                "run_id":
                    run_id,

                "change_detected":
                    change_detected,

                "changed_sections":
                    changed_sections,

                "classification":
                    (
                        "CHANGE_DETECTED"
                        if change_detected
                        else
                        "NO_CHANGE_DETECTED"
                    ),

                "security_severity":
                    "NOT_ASSERTED",

                "security_resolution":
                    "NOT_ASSERTED",

                "requires_human_review":
                    change_detected,

                "automatic_remediation":
                    False,

                "automatic_risk_acceptance":
                    False,

                "automatic_deferral":
                    False,
            }

            report = {
                "schema":
                    REPORT_SCHEMA,

                "run_id":
                    run_id,

                "generated_at":
                    utc_now(),

                "hostname":
                    payload.get(
                        "identity",
                        {}
                    ).get(
                        "hostname"
                    ),

                "initial_baseline":
                    initial_baseline,

                "change_detected":
                    change_detected,

                "changed_sections":
                    changed_sections,

                "package_change_counts":
                    {
                        "added":
                            len(
                                package_changes[
                                    "added"
                                ]
                            ),

                        "removed":
                            len(
                                package_changes[
                                    "removed"
                                ]
                            ),

                        "version_changed":
                            len(
                                package_changes[
                                    "version_changed"
                                ]
                            ),
                    },

                "security_resolution":
                    "NOT_ASSERTED",

                "llm_used":
                    False,
            }

            meta = {
                "schema":
                    "ia-security-agent-run-meta-v1",

                "run_id":
                    run_id,

                "created_at":
                    utc_now(),

                "payload_sha256":
                    payload_sha,

                "previous_run_id":
                    diff[
                        "previous_run_id"
                    ],
            }

            exclusive_json(
                stage
                / "observation-v1.json",
                observation,
            )

            exclusive_json(
                stage
                / "meta-v1.json",
                meta,
            )

            exclusive_json(
                stage
                / "diff-v1.json",
                diff,
            )

            exclusive_json(
                stage
                / "impact-v1.json",
                impact,
            )

            exclusive_json(
                stage
                / "incremental-report-v1.json",
                report,
            )

            artifacts = {}

            for name in (
                "observation-v1.json",
                "meta-v1.json",
                "diff-v1.json",
                "impact-v1.json",
                "incremental-report-v1.json",
            ):

                artifacts[name] = (
                    sha256_file(
                        stage / name
                    )
                )

            previous_commit_sha = (
                previous_head
                .get(
                    "current",
                    {}
                )
                .get(
                    "commit_sha256"
                )
                if previous_head
                else None
            )

            commit_unsigned = {
                "schema":
                    COMMIT_SCHEMA,

                "run_id":
                    run_id,

                "created_at":
                    utc_now(),

                "previous_commit_sha256":
                    previous_commit_sha,

                "artifacts":
                    artifacts,
            }

            commit_sha = (
                sha256_bytes(
                    canonical(
                        commit_unsigned
                    )
                )
            )

            commit = dict(
                commit_unsigned
            )

            commit[
                "commit_sha256"
            ] = commit_sha

            exclusive_json(
                stage
                / "cycle-commit-v1.json",
                commit,
            )

            for name, expected in (
                artifacts.items()
            ):

                if (
                    sha256_file(
                        stage / name
                    )
                    != expected
                ):
                    raise RuntimeError(
                        "staged artifact digest mismatch"
                    )

            os.rename(
                stage,
                run_target,
            )

            committed = True

            now = datetime.now(
                timezone.utc
            )

            year = now.strftime(
                "%Y"
            )

            month = now.strftime(
                "%m"
            )

            history_map = {
                "observation-v1.json":
                    runtime
                    / "history"
                    / "raw"
                    / year
                    / month
                    / (
                        payload.get(
                            "identity",
                            {}
                        ).get(
                            "hostname",
                            "host"
                        )
                        + "-security-audit-"
                        + run_id
                        + ".json"
                    ),

                "meta-v1.json":
                    runtime
                    / "history"
                    / "meta"
                    / year
                    / month
                    / (
                        run_id
                        + ".meta.json"
                    ),

                "diff-v1.json":
                    runtime
                    / "history"
                    / "diff"
                    / year
                    / month
                    / (
                        run_id
                        + ".diff.json"
                    ),

                "impact-v1.json":
                    runtime
                    / "history"
                    / "impact"
                    / year
                    / month
                    / (
                        run_id
                        + ".impact.json"
                    ),

                "incremental-report-v1.json":
                    runtime
                    / "reports"
                    / (
                        run_id
                        + ".incremental-report-v1.json"
                    ),

                "cycle-commit-v1.json":
                    runtime
                    / "commits"
                    / (
                        run_id
                        + ".cycle-commit-v1.json"
                    ),
            }

            for source_name, target in (
                history_map.items()
            ):

                target.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                    mode=0o750,
                )

                os.link(
                    run_target
                    / source_name,
                    target,
                )

            baseline_path = (
                runtime
                / "baseline"
                / "baseline-v1.json"
            )

            if initial_baseline:

                if baseline_path.exists():
                    raise RuntimeError(
                        "baseline unexpectedly exists"
                    )

                shutil.copyfile(
                    run_target
                    / "observation-v1.json",
                    baseline_path,
                )

                os.chmod(
                    baseline_path,
                    0o440,
                )

            elif not baseline_path.is_file():
                raise RuntimeError(
                    "baseline missing after initialization"
                )

            head = {
                "schema":
                    HEAD_SCHEMA,

                "updated_at":
                    utc_now(),

                "instance_id":
                    instance[
                        "identity"
                    ][
                        "instance_id"
                    ],

                "installation_id":
                    instance[
                        "identity"
                    ][
                        "installation_id"
                    ],

                "baseline":
                    {
                        "path":
                            relative_to_runtime(
                                baseline_path,
                                runtime,
                            ),

                        "sha256":
                            sha256_file(
                                baseline_path
                            ),
                    },

                "previous":
                    (
                        previous_head
                        .get("current")
                        if previous_head
                        else None
                    ),

                "current": {
                    "run_id":
                        run_id,

                    "run":
                        relative_to_runtime(
                            run_target,
                            runtime,
                        ),

                    "observation":
                        relative_to_runtime(
                            run_target
                            / "observation-v1.json",
                            runtime,
                        ),

                    "observation_sha256":
                        sha256_file(
                            run_target
                            / "observation-v1.json"
                        ),

                    "diff":
                        relative_to_runtime(
                            run_target
                            / "diff-v1.json",
                            runtime,
                        ),

                    "impact":
                        relative_to_runtime(
                            run_target
                            / "impact-v1.json",
                            runtime,
                        ),

                    "report":
                        relative_to_runtime(
                            run_target
                            / "incremental-report-v1.json",
                            runtime,
                        ),

                    "commit":
                        relative_to_runtime(
                            run_target
                            / "cycle-commit-v1.json",
                            runtime,
                        ),

                    "commit_sha256":
                        commit_sha,

                    "security_resolution":
                        "NOT_ASSERTED",
                },
            }

            atomic_replace_json(
                head_path,
                head,
            )

            state_history = (
                runtime
                / "state"
                / "history-state.json"
            )

            atomic_replace_json(
                state_history,
                {
                    "schema":
                        "ia-security-agent-history-state-v1",

                    "updated_at":
                        utc_now(),

                    "previous":
                        head[
                            "previous"
                        ],

                    "current":
                        head[
                            "current"
                        ],
                },
            )

        except Exception as exc:

            evidence = (
                materialize_failure(
                    runtime=runtime,
                    run_id=run_id,
                    stage=stage,
                    committed_run=
                        run_target,
                    error=exc,
                )
            )

            refuse(
                (
                    "DPL1.CORE.POST_COMMIT_FAILURE"
                    if committed
                    else
                    "DPL1.CORE.CYCLE_FAILED"
                ),
                {
                    "attempt_id":
                        run_id,

                    "error_type":
                        type(exc).__name__,

                    "failure_evidence":
                        evidence,

                    "committed_run_preserved":
                        committed,
                },
            )

        emit(
            status="VALID",
            reason_code=None,
            details={
                "run_id":
                    run_id,

                "initial_baseline":
                    initial_baseline,

                "change_detected":
                    change_detected,

                "changed_sections":
                    changed_sections,

                "payload_sha256":
                    payload_sha,

                "commit_sha256":
                    commit_sha,

                "head":
                    str(head_path),

                "security_resolution":
                    "NOT_ASSERTED",

                "automatic_remediation":
                    False,

                "llm_used":
                    False,
            },
        )

    finally:

        try:
            fcntl.flock(
                lock_fd,
                fcntl.LOCK_UN,
            )
        finally:
            os.close(
                lock_fd
            )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "IA Security Agent Deployment V1 "
            "deterministic longitudinal cycle"
        )
    )

    parser.add_argument(
        "--instance-config",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    cycle(
        args.instance_config
    )

    return EXIT_VALID


if __name__ == "__main__":
    raise SystemExit(main())
