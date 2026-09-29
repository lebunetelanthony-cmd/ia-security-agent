#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re

from pathlib import Path


RESULT_SCHEMA = "ia-security-agent-stage-result-v1"
INSTANCE_SCHEMA = "ia-security-agent-instance-config-v1"
LLM_SCHEMA = "ia-security-agent-nightly-llm-config-v1"

EXIT_REFUSED = 20

TOKEN_RE = re.compile(
    r"@[A-Z0-9_]+@"
)


def refuse(
    code: str,
    detail: str,
) -> "NoReturn":

    print(
        json.dumps(
            {
                "schema": RESULT_SCHEMA,
                "stage": "NIGHTLY_LLM_SYSTEMD_RENDER",
                "status": "REFUSED",
                "reason_code": code,
                "next_stage_authorized": False,
                "details": {
                    "error": detail,
                },
            },
            sort_keys=True,
            indent=2,
        )
    )

    raise SystemExit(EXIT_REFUSED)


def load(path: Path) -> dict:

    try:
        obj = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            type(exc).__name__,
        )

    if not isinstance(obj, dict):
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "root not object",
        )

    return obj


def render(
    source: str,
    values: dict[str, str],
) -> str:

    result = source

    for key, value in values.items():
        result = result.replace(
            f"@{key}@",
            value,
        )

    remaining = sorted(
        set(TOKEN_RE.findall(result))
    )

    if remaining:
        refuse(
            "DPL1.LLM.UNRESOLVED_TEMPLATE_TOKEN",
            ",".join(remaining),
        )

    return result


def write_exclusive(
    path: Path,
    data: str,
) -> None:

    fd = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL,
        0o640,
    )

    with os.fdopen(
        fd,
        "w",
        encoding="utf-8",
    ) as f:

        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def main() -> int:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--package-root",
        type=Path,
        required=True,
    )

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
        "--output-dir",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    package = args.package_root.resolve()
    instance_path = args.instance_config.resolve()
    llm_path = args.llm_config.resolve()
    output = args.output_dir.resolve(
        strict=False
    )

    if output.exists():
        refuse(
            "DPL1.LLM.SYSTEMD_OUTPUT_EXISTS",
            str(output),
        )

    instance = load(instance_path)
    llm = load(llm_path)

    if (
        instance.get("schema")
        != INSTANCE_SCHEMA
    ):
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "instance schema mismatch",
        )

    if llm.get("schema") != LLM_SCHEMA:
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "LLM schema mismatch",
        )

    runtime_value = (
        instance
        .get("filesystem", {})
        .get("runtime_root")
    )

    service = instance.get(
        "service",
        {}
    )

    if not isinstance(
        runtime_value,
        str,
    ):
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "runtime_root invalid",
        )

    runtime = Path(runtime_value).resolve()

    python_bin = service.get("python_bin")
    service_user = service.get("user")
    service_group = service.get("group")

    for name, value in (
        ("python_bin", python_bin),
        ("service_user", service_user),
        ("service_group", service_group),
    ):
        if (
            not isinstance(value, str)
            or not value
            or "\n" in value
            or "\r" in value
            or "\x00" in value
        ):
            refuse(
                "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
                f"{name} invalid",
            )

    if not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_.-]*",
        service_user,
    ):
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "service user invalid",
        )

    if not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_.-]*",
        service_group,
    ):
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "service group invalid",
        )

    python_path = Path(
        python_bin
    )

    if (
        not python_path.is_absolute()
        or not python_path.is_file()
        or not os.access(
            python_path,
            os.X_OK,
        )
    ):
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "python binary invalid",
        )

    schedule = llm.get(
        "schedule",
        {}
    )

    time_value = schedule.get("time")
    timezone_value = schedule.get(
        "timezone"
    )

    if (
        not isinstance(time_value, str)
        or not re.fullmatch(
            r"[0-2][0-9]:[0-5][0-9]:[0-5][0-9]",
            time_value,
        )
    ):
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "schedule time invalid",
        )

    if (
        not isinstance(timezone_value, str)
        or not timezone_value
        or any(
            c.isspace()
            for c in timezone_value
        )
        or ".." in Path(
            timezone_value
        ).parts
    ):
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "timezone invalid",
        )

    zonefile = (
        Path("/usr/share/zoneinfo")
        / timezone_value
    )

    if (
        timezone_value != "UTC"
        and not zonefile.is_file()
    ):
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "timezone not found",
        )

    engine = (
        package
        / "nightly-llm"
        / "nightly-llm-v5.py"
    ).resolve()

    entrypoint = (
        package
        / "bin"
        / "nightly-llm-ia-security-agent"
    ).resolve()

    if (
        not engine.is_file()
        or not entrypoint.is_file()
    ):
        refuse(
            "DPL1.LLM.SYSTEMD_COMPONENT_MISSING",
            "engine or entrypoint missing",
        )

    expected_instance = (
        runtime
        / "config"
        / "instance-config-v1.json"
    ).resolve()

    expected_llm = (
        runtime
        / "config"
        / "nightly-llm-v1.json"
    ).resolve()

    if expected_instance != instance_path:
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "instance binding mismatch",
        )

    if expected_llm != llm_path:
        refuse(
            "DPL1.LLM.SYSTEMD_CONFIG_INVALID",
            "LLM binding mismatch",
        )

    service_template = (
        package
        / "systemd"
        / "ia-security-agent-nightly-llm.service.in"
    )

    timer_template = (
        package
        / "systemd"
        / "ia-security-agent-nightly-llm.timer.in"
    )

    if (
        not service_template.is_file()
        or not timer_template.is_file()
    ):
        refuse(
            "DPL1.LLM.SYSTEMD_COMPONENT_MISSING",
            "templates missing",
        )

    output.mkdir(
        mode=0o750
    )

    values = {
        "PACKAGE_ROOT":
            str(package),
        "RUNTIME_ROOT":
            str(runtime),
        "INSTANCE_CONFIG":
            str(instance_path),
        "LLM_CONFIG":
            str(llm_path),
        "LLM_ENTRYPOINT":
            str(entrypoint),
        "LLM_ENGINE":
            str(engine),
        "PYTHON_BIN":
            str(python_path),
        "SERVICE_USER":
            service_user,
        "SERVICE_GROUP":
            service_group,
        "ON_CALENDAR":
            "*-*-* "
            + time_value
            + " "
            + timezone_value,
    }

    service_out = (
        output
        / "ia-security-agent-nightly-llm.service"
    )

    timer_out = (
        output
        / "ia-security-agent-nightly-llm.timer"
    )

    write_exclusive(
        service_out,
        render(
            service_template.read_text(
                encoding="utf-8"
            ),
            values,
        ),
    )

    write_exclusive(
        timer_out,
        render(
            timer_template.read_text(
                encoding="utf-8"
            ),
            values,
        ),
    )

    print(
        json.dumps(
            {
                "schema":
                    RESULT_SCHEMA,
                "stage":
                    "NIGHTLY_LLM_SYSTEMD_RENDER",
                "status":
                    "VALID",
                "reason_code":
                    None,
                "next_stage_authorized":
                    True,
                "details": {
                    "service":
                        str(service_out),
                    "timer":
                        str(timer_out),
                    "installed":
                        False,
                    "activated":
                        False,
                },
            },
            sort_keys=True,
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
