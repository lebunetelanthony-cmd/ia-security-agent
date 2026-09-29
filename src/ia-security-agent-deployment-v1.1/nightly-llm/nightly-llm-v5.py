#!/usr/bin/env python3
"""
IA Security Agent Deployment V1.1
Generic Nightly LLM engine — V5 publication semantics.

This module is intentionally non-authoritative. It consumes deterministic
agent state and can never remediate, accept risk, defer risk, or assert
security resolution.

V5 invariants carried into this generic deployment engine:
- strict JSON output schema + validator alignment
- raw request/envelope/response preservation
- attempt directories requested with mode 0750 (SGID-compatible)
- no attempts -> runs/failures inter-directory rename
- verified evidence copy into .pending-* under destination parent
- final rename occurs only inside the same parent
- append-only publication
- failure evidence preservation
- no automatic retry
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import urllib.parse
import urllib.request

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RESULT_SCHEMA = "ia-security-agent-stage-result-v1"
INSTANCE_SCHEMA = "ia-security-agent-instance-config-v1"
LLM_SCHEMA = "ia-security-agent-nightly-llm-config-v1"
ANALYSIS_SCHEMA = "nightly-security-analysis-v1"

IMPLEMENTATION_REVISION = "nightly-llm-v5-generic"

ALLOWED_ASSESSMENTS = {
    "NO_NEW_DEGRADATION",
    "ATTENTION_REQUIRED",
    "DEGRADATION_OBSERVED",
    "INSUFFICIENT_EVIDENCE",
}

ALLOWED_REFS = {
    "core_head",
}

REQUIRED_ANALYSIS_KEYS = {
    "schema",
    "non_authoritative",
    "assessment",
    "summary",
    "observations",
    "uncertainties",
    "human_review_recommended",
}


class Refused(Exception):

    def __init__(
        self,
        reason_code: str,
        details: dict[str, Any] | None = None,
    ) -> None:

        super().__init__(reason_code)
        self.reason_code = reason_code
        self.details = details or {}


def utc_now() -> str:

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def create_run_id() -> str:

    return (
        datetime.now(timezone.utc)
        .strftime("%Y%m%dT%H%M%S%fZ")
        + "--"
        + secrets.token_hex(4)
    )


def json_bytes(
    obj: Any,
) -> bytes:

    return (
        json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def pretty_json_bytes(
    obj: Any,
) -> bytes:

    return (
        json.dumps(
            obj,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(
    data: bytes,
) -> str:

    return hashlib.sha256(data).hexdigest()


def sha256_file(
    path: Path,
) -> str:

    h = hashlib.sha256()

    with path.open("rb") as fh:

        for block in iter(
            lambda: fh.read(1024 * 1024),
            b"",
        ):
            h.update(block)

    return h.hexdigest()


def secure_create_bytes(
    path: Path,
    data: bytes,
    mode: int = 0o640,
) -> None:

    fd = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL,
        mode,
    )

    with os.fdopen(fd, "wb") as fh:

        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def secure_create_json(
    path: Path,
    obj: Any,
    mode: int = 0o640,
) -> None:

    secure_create_bytes(
        path,
        pretty_json_bytes(obj),
        mode,
    )


def load_json(
    path: Path,
) -> Any:

    with path.open(
        "r",
        encoding="utf-8",
    ) as fh:

        return json.load(fh)


def emit(
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
                    "NIGHTLY_LLM",

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
    **details: Any,
) -> "NoReturn":

    raise Refused(
        code,
        details,
    )


def resolve_under(
    root: Path,
    relative: str,
) -> Path:

    if (
        not relative
        or "\x00" in relative
        or "\n" in relative
        or "\r" in relative
    ):
        refuse(
            "DPL1.LLM.INPUT_PATH_INVALID",
            value=relative,
        )

    rel = Path(relative)

    if rel.is_absolute() or ".." in rel.parts:
        refuse(
            "DPL1.LLM.INPUT_PATH_INVALID",
            value=relative,
        )

    candidate = (
        root
        / rel
    ).resolve(
        strict=False
    )

    try:
        candidate.relative_to(root)
    except ValueError:
        refuse(
            "DPL1.LLM.INPUT_PATH_INVALID",
            value=relative,
        )

    return candidate


def validate_loopback_endpoint(
    endpoint: str,
) -> str:

    parsed = urllib.parse.urlparse(
        endpoint
    )

    if (
        parsed.scheme != "http"
        or parsed.hostname
        not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }
        or parsed.port is None
    ):
        refuse(
            "DPL1.LLM.CONFIG_INVALID",
            error="loopback HTTP Ollama endpoint required",
        )

    if (
        parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        refuse(
            "DPL1.LLM.CONFIG_INVALID",
            error="endpoint must be origin only",
        )

    return endpoint.rstrip("/")


def output_schema() -> dict[str, Any]:

    return {
        "type":
            "object",

        "additionalProperties":
            False,

        "required":
            [
                "schema",
                "non_authoritative",
                "assessment",
                "summary",
                "observations",
                "uncertainties",
                "human_review_recommended",
            ],

        "properties": {
            "schema": {
                "type":
                    "string",
                "const":
                    ANALYSIS_SCHEMA,
            },

            "non_authoritative": {
                "type":
                    "boolean",
                "const":
                    True,
            },

            "assessment": {
                "type":
                    "string",
                "enum":
                    sorted(
                        ALLOWED_ASSESSMENTS
                    ),
            },

            "summary": {
                "type":
                    "string",
            },

            "observations": {
                "type":
                    "array",

                "items": {
                    "type":
                        "object",

                    "additionalProperties":
                        False,

                    "required":
                        [
                            "title",
                            "rationale",
                            "evidence_refs",
                        ],

                    "properties": {
                        "title": {
                            "type":
                                "string",
                        },

                        "rationale": {
                            "type":
                                "string",
                        },

                        "evidence_refs": {
                            "type":
                                "array",

                            "items": {
                                "type":
                                    "string",
                                "enum":
                                    sorted(
                                        ALLOWED_REFS
                                    ),
                            },
                        },
                    },
                },
            },

            "uncertainties": {
                "type":
                    "array",

                "items": {
                    "type":
                        "string",
                },
            },

            "human_review_recommended": {
                "type":
                    "boolean",
            },
        },
    }


def validate_analysis(
    analysis: Any,
) -> None:

    if not isinstance(
        analysis,
        dict,
    ):
        refuse(
            "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
            error="analysis root must be object",
        )

    keys = set(
        analysis.keys()
    )

    if keys != REQUIRED_ANALYSIS_KEYS:

        refuse(
            "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
            error="analysis keys mismatch",
            missing=sorted(
                REQUIRED_ANALYSIS_KEYS
                - keys
            ),
            extra=sorted(
                keys
                - REQUIRED_ANALYSIS_KEYS
            ),
        )

    if analysis["schema"] != ANALYSIS_SCHEMA:
        refuse(
            "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
            field="schema",
        )

    if analysis["non_authoritative"] is not True:
        refuse(
            "DPL1.LLM.AUTHORITY_POLICY_INVALID",
            field="non_authoritative",
        )

    if (
        not isinstance(
            analysis["assessment"],
            str,
        )
        or analysis["assessment"]
        not in ALLOWED_ASSESSMENTS
    ):
        refuse(
            "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
            field="assessment",
        )

    summary = analysis["summary"]

    if (
        not isinstance(summary, str)
        or not summary.strip()
        or len(summary) > 12000
    ):
        refuse(
            "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
            field="summary",
        )

    observations = analysis[
        "observations"
    ]

    if (
        not isinstance(
            observations,
            list,
        )
        or len(observations) > 128
    ):
        refuse(
            "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
            field="observations",
        )

    for index, observation in enumerate(
        observations
    ):

        if not isinstance(
            observation,
            dict,
        ):
            refuse(
                "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
                field=f"observations[{index}]",
            )

        expected = {
            "title",
            "rationale",
            "evidence_refs",
        }

        if set(
            observation.keys()
        ) != expected:
            refuse(
                "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
                field=f"observations[{index}]",
                error="keys mismatch",
            )

        for field in (
            "title",
            "rationale",
        ):

            value = observation[field]

            if (
                not isinstance(
                    value,
                    str,
                )
                or not value.strip()
                or len(value) > 8000
            ):
                refuse(
                    "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
                    field=(
                        f"observations[{index}]."
                        + field
                    ),
                )

        refs = observation[
            "evidence_refs"
        ]

        if (
            not isinstance(
                refs,
                list,
            )
            or len(refs) > 32
        ):
            refuse(
                "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
                field=(
                    f"observations[{index}]"
                    ".evidence_refs"
                ),
            )

        for ref in refs:

            if ref not in ALLOWED_REFS:
                refuse(
                    "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
                    field=(
                        f"observations[{index}]"
                        ".evidence_refs"
                    ),
                    invalid_ref=ref,
                )

    uncertainties = analysis[
        "uncertainties"
    ]

    if (
        not isinstance(
            uncertainties,
            list,
        )
        or len(uncertainties) > 128
        or any(
            not isinstance(item, str)
            or len(item) > 8000
            for item in uncertainties
        )
    ):
        refuse(
            "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
            field="uncertainties",
        )

    if not isinstance(
        analysis[
            "human_review_recommended"
        ],
        bool,
    ):
        refuse(
            "DPL1.LLM.ANALYSIS_SCHEMA_INVALID",
            field="human_review_recommended",
        )


def http_json(
    url: str,
    *,
    method: str = "GET",
    obj: Any | None = None,
    timeout: int = 45,
) -> tuple[
    dict[str, Any],
    bytes,
]:

    data = None
    headers = {}

    if obj is not None:

        data = json_bytes(
            obj
        )

        headers[
            "Content-Type"
        ] = "application/json"

    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:

            raw = response.read()

    except Exception as exc:

        refuse(
            "DPL1.LLM.PROVIDER_UNAVAILABLE",
            url=url,
            error_type=type(exc).__name__,
        )

    try:

        parsed = json.loads(
            raw.decode("utf-8")
        )

    except Exception:

        refuse(
            "DPL1.LLM.PROVIDER_RESPONSE_INVALID",
            url=url,
        )

    if not isinstance(
        parsed,
        dict,
    ):
        refuse(
            "DPL1.LLM.PROVIDER_RESPONSE_INVALID",
            url=url,
        )

    return parsed, raw


def verify_provider(
    llm: dict[str, Any],
) -> dict[str, Any]:

    endpoint = validate_loopback_endpoint(
        llm.get(
            "endpoint",
            "",
        )
    )

    if llm.get(
        "provider"
    ) != "ollama":
        refuse(
            "DPL1.LLM.CONFIG_INVALID",
            field="provider",
        )

    version_obj, _ = http_json(
        endpoint
        + "/api/version",
        timeout=15,
    )

    observed_version = (
        version_obj.get(
            "version"
        )
    )

    expected_version = (
        llm.get(
            "provider_version"
        )
    )

    if (
        not isinstance(
            observed_version,
            str,
        )
        or not observed_version
    ):
        refuse(
            "DPL1.LLM.PROVIDER_VERSION_MISMATCH",
            observed=observed_version,
        )

    if (
        isinstance(
            expected_version,
            str,
        )
        and expected_version
        and observed_version
        != expected_version
    ):
        refuse(
            "DPL1.LLM.PROVIDER_VERSION_MISMATCH",
            expected=expected_version,
            observed=observed_version,
        )

    tags, _ = http_json(
        endpoint
        + "/api/tags",
        timeout=15,
    )

    models = tags.get(
        "models"
    )

    if not isinstance(
        models,
        list,
    ):
        refuse(
            "DPL1.LLM.MODEL_MISSING",
        )

    expected_model = llm.get(
        "model"
    )

    expected_digest = llm.get(
        "model_digest"
    )

    if (
        not isinstance(
            expected_model,
            str,
        )
        or not expected_model
    ):
        refuse(
            "DPL1.LLM.CONFIG_INVALID",
            field="model",
        )

    if (
        not isinstance(
            expected_digest,
            str,
        )
        or not re.fullmatch(
            r"(?:sha256:)?[0-9a-f]{64}",
            expected_digest,
        )
    ):
        refuse(
            "DPL1.LLM.CONFIG_INVALID",
            field="model_digest",
        )

    expected_digest = (
        expected_digest.removeprefix(
            "sha256:"
        )
    )

    selected = None

    for candidate in models:

        if not isinstance(
            candidate,
            dict,
        ):
            continue

        if (
            candidate.get("name")
            == expected_model
            or candidate.get("model")
            == expected_model
        ):

            selected = candidate
            break

    if selected is None:

        refuse(
            "DPL1.LLM.MODEL_MISSING",
            model=expected_model,
        )

    observed_digest = selected.get(
        "digest"
    )

    if isinstance(
        observed_digest,
        str,
    ):
        observed_digest = (
            observed_digest
            .removeprefix(
                "sha256:"
            )
        )

    if (
        observed_digest
        != expected_digest
    ):
        refuse(
            "DPL1.LLM.MODEL_DIGEST_MISMATCH",
            expected=expected_digest,
            observed=observed_digest,
        )

    return {
        "endpoint":
            endpoint,

        "provider":
            "ollama",

        "provider_version":
            observed_version,

        "model":
            expected_model,

        "model_digest":
            expected_digest,
    }


def build_prompt(
    head: Any,
) -> str:

    context = json.dumps(
        head,
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
    )

    return (
        "You are a non-authoritative security analysis consumer. "
        "You MUST return only one JSON object matching the supplied "
        "JSON schema. Do not output markdown or commentary. "
        "Do not claim remediation, risk acceptance, deferral, or "
        "security resolution. Set non_authoritative to true. "
        "Use only evidence_refs from the allowed set: core_head. "
        "If the deterministic evidence is insufficient, use "
        "INSUFFICIENT_EVIDENCE and describe the uncertainty. "
        "The following object is deterministic IA Security Agent "
        "HEAD evidence. Analyze only what is present.\n\n"
        + context
    )


def write_sha256s(
    directory: Path,
) -> None:

    sums_path = (
        directory
        / "SHA256SUMS"
    )

    names = sorted(
        path.name
        for path in directory.iterdir()
        if path.is_file()
        and path.name
        != "SHA256SUMS"
    )

    lines = [
        sha256_file(
            directory / name
        )
        + "  "
        + name
        for name in names
    ]

    secure_create_bytes(
        sums_path,
        (
            "\n".join(lines)
            + "\n"
        ).encode("utf-8"),
        0o640,
    )


def verify_sha256s(
    directory: Path,
) -> None:

    sums_path = (
        directory
        / "SHA256SUMS"
    )

    if not sums_path.is_file():

        refuse(
            "DPL1.LLM.EVIDENCE_SUMS_MISSING",
            directory=str(directory),
        )

    for line in sums_path.read_text(
        encoding="utf-8"
    ).splitlines():

        if not line.strip():
            continue

        try:
            digest, name = (
                line.split(
                    "  ",
                    1,
                )
            )
        except ValueError:
            refuse(
                "DPL1.LLM.EVIDENCE_SUMS_INVALID",
                directory=str(directory),
            )

        path = directory / name

        if (
            not path.is_file()
            or sha256_file(path)
            != digest
        ):
            refuse(
                "DPL1.LLM.EVIDENCE_SUMS_INVALID",
                file=name,
            )


def freeze_directory(
    directory: Path,
) -> None:

    for path in sorted(
        directory.rglob("*"),
        key=lambda p:
            len(p.parts),
        reverse=True,
    ):

        if path.is_symlink():
            refuse(
                "DPL1.LLM.EVIDENCE_SYMLINK_FOUND",
                path=str(path),
            )

        if path.is_file():
            os.chmod(
                path,
                0o440,
            )

        elif path.is_dir():
            os.chmod(
                path,
                0o550,
            )

    os.chmod(
        directory,
        0o550,
    )


def copy_evidence_payload(
    source: Path,
    pending: Path,
) -> None:

    if pending.exists():
        refuse(
            "DPL1.LLM.PENDING_DESTINATION_EXISTS",
            path=str(pending),
        )

    pending.mkdir(
        mode=0o0750,
    )

    for path in sorted(
        source.iterdir(),
        key=lambda p:
            p.name,
    ):

        if path.is_symlink():
            refuse(
                "DPL1.LLM.EVIDENCE_SYMLINK_FOUND",
                path=str(path),
            )

        if not path.is_file():
            refuse(
                "DPL1.LLM.EVIDENCE_LAYOUT_INVALID",
                path=str(path),
            )

        destination = (
            pending
            / path.name
        )

        data = path.read_bytes()

        secure_create_bytes(
            destination,
            data,
            0o640,
        )

        if (
            sha256_file(path)
            != sha256_file(
                destination
            )
        ):
            refuse(
                "DPL1.LLM.VERIFIED_COPY_FAILED",
                file=path.name,
            )


def publish_copy(
    source: Path,
    parent: Path,
    run_id: str,
) -> Path:

    parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o750,
    )

    final = parent / run_id
    pending = (
        parent
        / (
            ".pending-"
            + run_id
        )
    )

    if (
        final.exists()
        or pending.exists()
    ):
        refuse(
            "DPL1.LLM.PUBLICATION_CONFLICT",
            run_id=run_id,
            parent=str(parent),
        )

    copy_evidence_payload(
        source,
        pending,
    )

    verify_sha256s(
        pending
    )

    freeze_directory(
        pending
    )

    # V5 rule: this rename is inside the same parent only.
    pending.rename(
        final
    )

    return final


def publish_success_copy(
    attempt: Path,
    runs_parent: Path,
    run_id: str,
) -> Path:

    return publish_copy(
        attempt,
        runs_parent,
        run_id,
    )


def publish_failure_copy(
    attempt: Path,
    failures_parent: Path,
    run_id: str,
) -> Path:

    return publish_copy(
        attempt,
        failures_parent,
        run_id,
    )


def validate_configs(
    instance_path: Path,
    llm_path: Path,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    Path,
    Path,
]:

    instance = load_json(
        instance_path
    )

    llm = load_json(
        llm_path
    )

    if (
        not isinstance(
            instance,
            dict,
        )
        or instance.get(
            "schema"
        )
        != INSTANCE_SCHEMA
    ):
        refuse(
            "DPL1.LLM.INSTANCE_CONFIG_INVALID",
        )

    if (
        not isinstance(
            llm,
            dict,
        )
        or llm.get(
            "schema"
        )
        != LLM_SCHEMA
    ):
        refuse(
            "DPL1.LLM.CONFIG_INVALID",
            field="schema",
        )

    if llm.get(
        "enabled"
    ) is not True:
        refuse(
            "DPL1.LLM.DISABLED",
        )

    if llm.get(
        "authority"
    ) != "NON_FACTUAL_CONSUMER":
        refuse(
            "DPL1.LLM.AUTHORITY_POLICY_INVALID",
            field="authority",
        )

    runtime_value = (
        instance
        .get("filesystem", {})
        .get("runtime_root")
    )

    if (
        not isinstance(
            runtime_value,
            str,
        )
        or not runtime_value
    ):
        refuse(
            "DPL1.LLM.INSTANCE_CONFIG_INVALID",
            field="filesystem.runtime_root",
        )

    runtime = Path(
        runtime_value
    ).resolve()

    if not runtime.is_dir():
        refuse(
            "DPL1.LLM.RUNTIME_ROOT_MISSING",
            runtime_root=str(runtime),
        )

    input_relative = llm.get(
        "input_relative_path"
    )

    if not isinstance(
        input_relative,
        str,
    ):
        refuse(
            "DPL1.LLM.CONFIG_INVALID",
            field="input_relative_path",
        )

    input_path = resolve_under(
        runtime,
        input_relative,
    )

    if not input_path.is_file():
        refuse(
            "DPL1.LLM.INPUT_MISSING",
            path=str(input_path),
        )

    return (
        instance,
        llm,
        runtime,
        input_path,
    )


def materialize_failure(
    *,
    attempt: Path,
    failures_parent: Path,
    run_id: str,
    reason_code: str,
    details: dict[str, Any],
) -> Path:

    refusal = {
        "schema":
            "ia-security-agent-nightly-llm-refusal-v1",

        "implementation_revision":
            IMPLEMENTATION_REVISION,

        "status":
            "REFUSED",

        "reason_code":
            reason_code,

        "run_id":
            run_id,

        "created_at":
            utc_now(),

        "same_attempt_retry_allowed":
            False,

        "append_only":
            True,

        "automatic_retry":
            False,

        "automatic_remediation":
            False,

        "automatic_risk_acceptance":
            False,

        "automatic_deferral":
            False,

        "details":
            details,
    }

    refusal_path = (
        attempt
        / "REFUSED.json"
    )

    if not refusal_path.exists():

        secure_create_json(
            refusal_path,
            refusal,
        )

    sums = attempt / "SHA256SUMS"

    if sums.exists():
        os.chmod(
            sums,
            0o640,
        )
        sums.unlink()

    write_sha256s(
        attempt
    )

    try:

        destination = publish_failure_copy(
            attempt,
            failures_parent,
            run_id,
        )

    except Exception:

        destination = attempt

    try:
        freeze_directory(
            attempt
        )
    except Exception:
        pass

    return destination


def preflight(
    instance_path: Path,
    llm_path: Path,
) -> dict[str, Any]:

    (
        _instance,
        llm,
        runtime,
        input_path,
    ) = validate_configs(
        instance_path,
        llm_path,
    )

    provider = verify_provider(
        llm
    )

    return {
        "mode":
            "PREFLIGHT",

        "implementation_revision":
            IMPLEMENTATION_REVISION,

        "authority":
            "NON_FACTUAL_CONSUMER",

        "input":
            str(input_path),

        "input_sha256":
            sha256_file(
                input_path
            ),

        "runtime_root":
            str(runtime),

        **provider,

        "llm_inference_executed":
            False,

        "mutation":
            "NONE",
    }


def run_analysis(
    instance_path: Path,
    llm_path: Path,
) -> dict[str, Any]:

    (
        _instance,
        llm,
        runtime,
        input_path,
    ) = validate_configs(
        instance_path,
        llm_path,
    )

    provider = verify_provider(
        llm
    )

    run_id = create_run_id()

    attempts_parent = (
        runtime
        / "attempts"
        / "nightly-llm"
    )

    runs_parent = (
        runtime
        / "runs"
        / "nightly-llm"
    )

    failures_parent = (
        runtime
        / "failures"
        / "nightly-llm"
    )

    for directory in (
        attempts_parent,
        runs_parent,
        failures_parent,
    ):
        directory.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o750,
        )

    attempt = (
        attempts_parent
        / run_id
    )

    # V5 SGID compatibility rule:
    # requested attempt mode is 0750, never 2750.
    attempt.mkdir(
        mode=0o0750,
    )

    try:

        head = load_json(
            input_path
        )

        input_record = {
            "schema":
                "ia-security-agent-nightly-llm-input-v1",

            "implementation_revision":
                IMPLEMENTATION_REVISION,

            "created_at":
                utc_now(),

            "evidence_ref":
                "core_head",

            "source_path":
                str(input_path),

            "source_sha256":
                sha256_file(
                    input_path
                ),

            "payload":
                head,
        }

        secure_create_json(
            attempt
            / "input-v1.json",
            input_record,
        )

        runtime_record = {
            "schema":
                "ia-security-agent-nightly-llm-runtime-v1",

            "implementation_revision":
                IMPLEMENTATION_REVISION,

            "created_at":
                utc_now(),

            "authority":
                "NON_FACTUAL_CONSUMER",

            "automatic_remediation":
                False,

            "automatic_risk_acceptance":
                False,

            "automatic_deferral":
                False,

            **provider,
        }

        secure_create_json(
            attempt
            / "runtime-v1.json",
            runtime_record,
        )

        prompt = build_prompt(
            head
        )

        request_obj = {
            "model":
                provider[
                    "model"
                ],

            "prompt":
                prompt,

            "stream":
                False,

            "think":
                False,

            "options": {
                "num_ctx":
                    16384,

                "num_predict":
                    2048,

                "temperature":
                    0,

                "seed":
                    0,
            },

            "format":
                output_schema(),
        }

        secure_create_json(
            attempt
            / "request-v1.json",
            {
                "schema":
                    "ia-security-agent-nightly-llm-request-v1",

                "implementation_revision":
                    IMPLEMENTATION_REVISION,

                "model":
                    provider[
                        "model"
                    ],

                "prompt_sha256":
                    sha256_bytes(
                        prompt.encode(
                            "utf-8"
                        )
                    ),

                "output_schema":
                    output_schema(),
            },
        )

        # Raw request bytes are preserved before inference.
        secure_create_bytes(
            attempt
            / "llm-request-raw-v1.json",
            json_bytes(
                request_obj
            ),
        )

        envelope, envelope_raw = http_json(
            provider["endpoint"]
            + "/api/generate",
            method="POST",
            obj=request_obj,
            timeout=1200,
        )

        # Raw provider envelope is preserved before interpretation.
        secure_create_bytes(
            attempt
            / "ollama-envelope-raw-v1.json",
            envelope_raw,
        )

        response_text = envelope.get(
            "response"
        )

        if not isinstance(
            response_text,
            str,
        ):
            refuse(
                "DPL1.LLM.RESPONSE_TEXT_MISSING",
            )

        # Raw textual LLM response is preserved before parsing.
        secure_create_bytes(
            attempt
            / "llm-response-raw-v1.txt",
            response_text.encode(
                "utf-8"
            ),
        )

        try:

            unvalidated = json.loads(
                response_text
            )

        except Exception as exc:

            secure_create_json(
                attempt
                / "llm-validation-error-v1.json",
                {
                    "schema":
                        "ia-security-agent-nightly-llm-validation-error-v1",

                    "error":
                        "JSON_PARSE_FAILED",

                    "error_type":
                        type(exc).__name__,
                },
            )

            refuse(
                "DPL1.LLM.ANALYSIS_JSON_INVALID",
                error_type=
                    type(exc).__name__,
            )

        secure_create_json(
            attempt
            / "llm-analysis-unvalidated-v1.json",
            unvalidated,
        )

        try:

            validate_analysis(
                unvalidated
            )

        except Refused as exc:

            secure_create_json(
                attempt
                / "llm-validation-error-v1.json",
                {
                    "schema":
                        "ia-security-agent-nightly-llm-validation-error-v1",

                    "reason_code":
                        exc.reason_code,

                    "details":
                        exc.details,
                },
            )

            raise

        secure_create_json(
            attempt
            / "analysis-v1.json",
            unvalidated,
        )

        secure_create_json(
            attempt
            / "response-envelope-v1.json",
            {
                "schema":
                    "ia-security-agent-nightly-llm-response-envelope-v1",

                "implementation_revision":
                    IMPLEMENTATION_REVISION,

                "provider":
                    provider[
                        "provider"
                    ],

                "provider_version":
                    provider[
                        "provider_version"
                    ],

                "model":
                    provider[
                        "model"
                    ],

                "model_digest":
                    provider[
                        "model_digest"
                    ],

                "done":
                    envelope.get(
                        "done"
                    ),
            },
        )

        manifest = {
            "schema":
                "ia-security-agent-nightly-llm-run-manifest-v1",

            "implementation_revision":
                IMPLEMENTATION_REVISION,

            "run_id":
                run_id,

            "created_at":
                utc_now(),

            "authority":
                "NON_FACTUAL_CONSUMER",

            "authoritative_security_state":
                False,

            "automatic_remediation":
                False,

            "automatic_risk_acceptance":
                False,

            "automatic_deferral":
                False,

            "input_sha256":
                sha256_file(
                    input_path
                ),

            "assessment":
                unvalidated[
                    "assessment"
                ],

            "human_review_recommended":
                unvalidated[
                    "human_review_recommended"
                ],

            "verified_copy_publication":
                True,

            "interdirectory_rename":
                False,

            "same_parent_final_rename":
                True,

            "raw_response_preservation":
                True,

            "attempt_mkdir_requested_mode":
                "0750",
        }

        secure_create_json(
            attempt
            / "manifest-v1.json",
            manifest,
        )

        write_sha256s(
            attempt
        )

        verify_sha256s(
            attempt
        )

        destination = publish_success_copy(
            attempt,
            runs_parent,
            run_id,
        )

        freeze_directory(
            attempt
        )

        return {
            "attempt_id":
                run_id,

            "run":
                str(destination),

            "implementation_revision":
                IMPLEMENTATION_REVISION,

            "authority":
                "NON_FACTUAL_CONSUMER",

            "authoritative_security_state":
                False,

            "assessment":
                unvalidated[
                    "assessment"
                ],

            "human_review_recommended":
                unvalidated[
                    "human_review_recommended"
                ],

            "input":
                str(input_path),

            "input_sha256":
                sha256_file(
                    input_path
                ),

            "provider":
                provider[
                    "provider"
                ],

            "provider_version":
                provider[
                    "provider_version"
                ],

            "model":
                provider[
                    "model"
                ],

            "model_digest":
                provider[
                    "model_digest"
                ],

            "verified_copy_publication":
                True,

            "interdirectory_rename":
                False,

            "same_parent_final_rename":
                True,

            "raw_response_preservation":
                True,

            "automatic_retry":
                False,

            "automatic_remediation":
                False,

            "automatic_risk_acceptance":
                False,

            "automatic_deferral":
                False,
        }

    except Refused as exc:

        destination = materialize_failure(
            attempt=attempt,
            failures_parent=
                failures_parent,
            run_id=run_id,
            reason_code=
                exc.reason_code,
            details=
                exc.details,
        )

        raise Refused(
            exc.reason_code,
            {
                **exc.details,

                "attempt_id":
                    run_id,

                "failure_evidence":
                    str(destination),

                "same_attempt_retry_allowed":
                    False,

                "raw_evidence_preserved":
                    True,
            },
        )

    except Exception as exc:

        destination = materialize_failure(
            attempt=attempt,
            failures_parent=
                failures_parent,
            run_id=run_id,
            reason_code=
                "DPL1.LLM.UNEXPECTED_FAILURE",
            details={
                "error_type":
                    type(exc).__name__,
            },
        )

        raise Refused(
            "DPL1.LLM.UNEXPECTED_FAILURE",
            {
                "error_type":
                    type(exc).__name__,

                "attempt_id":
                    run_id,

                "failure_evidence":
                    str(destination),

                "same_attempt_retry_allowed":
                    False,

                "raw_evidence_preserved":
                    True,
            },
        )


def main() -> int:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--instance-config",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--llm-config",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--validate-only",
        action="store_true",
    )

    parser.add_argument(
        "--preflight",
        action="store_true",
    )

    args = parser.parse_args()

    instance_path = (
        args.instance_config
        .resolve()
    )

    llm_path = (
        args.llm_config
        .resolve()
    )

    try:

        details = preflight(
            instance_path,
            llm_path,
        )

        if (
            args.validate_only
            or args.preflight
        ):

            if args.preflight:
                print(
                    "NIGHTLY_LLM_PREFLIGHT=VALID",
                    file=sys.stderr,
                )
                print(
                    "LLM_INFERENCE_EXECUTED=false",
                    file=sys.stderr,
                )

            emit(
                "VALID",
                None,
                {
                    **details,

                    "mode":
                        "VALIDATE_ONLY",

                    "llm_inference_executed":
                        False,
                },
            )

            return 0

        result = run_analysis(
            instance_path,
            llm_path,
        )

        emit(
            "VALID",
            None,
            result,
        )

        return 0

    except Refused as exc:

        emit(
            "REFUSED",
            exc.reason_code,
            {
                **exc.details,

                "implementation_revision":
                    IMPLEMENTATION_REVISION,

                "authority":
                    "NON_FACTUAL_CONSUMER",

                "automatic_retry":
                    False,

                "automatic_remediation":
                    False,

                "automatic_risk_acceptance":
                    False,

                "automatic_deferral":
                    False,
            },
        )

        return 20


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
