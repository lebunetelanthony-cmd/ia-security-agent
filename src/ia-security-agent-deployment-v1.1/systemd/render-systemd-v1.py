#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from pathlib import Path


EXIT_VALID = 0
EXIT_REFUSED = 20

INSTANCE_SCHEMA = (
    "ia-security-agent-instance-config-v1"
)

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
                "schema":
                    "ia-security-agent-stage-result-v1",
                "stage":
                    "SYSTEMD_RENDER",
                "status":
                    "REFUSED",
                "reason_code":
                    code,
                "next_stage_authorized":
                    False,
                "details": {
                    "error":
                        detail
                },
            },
            sort_keys=True,
            indent=2,
        )
    )

    raise SystemExit(EXIT_REFUSED)


def safe_atom(
    name: str,
    value: str,
) -> str:

    if not value:
        raise ValueError(
            f"{name} empty"
        )

    if any(
        x in value
        for x in (
            "\n",
            "\r",
            "\x00",
        )
    ):
        raise ValueError(
            f"{name} contains control character"
        )

    return value


def safe_absolute_path(
    name: str,
    value: str,
) -> Path:

    safe_atom(name, value)

    p = Path(value)

    if not p.is_absolute():
        raise ValueError(
            f"{name} must be absolute"
        )

    if any(
        c.isspace()
        for c in value
    ):
        raise ValueError(
            f"{name} contains whitespace"
        )

    return p.resolve(
        strict=False
    )


def load_config(
    path: Path,
) -> dict:

    if not path.is_file():
        refuse(
            "DPL1.SYSTEMD.CONFIG_MISSING",
            str(path),
        )

    try:
        data = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        refuse(
            "DPL1.SYSTEMD.CONFIG_INVALID",
            type(exc).__name__,
        )

    if (
        not isinstance(data, dict)
        or data.get("schema")
        != INSTANCE_SCHEMA
    ):
        refuse(
            "DPL1.SYSTEMD.CONFIG_INVALID",
            "instance schema mismatch",
        )

    return data


def render(
    template: str,
    values: dict[str, str],
) -> str:

    result = template

    for key, value in values.items():
        result = result.replace(
            f"@{key}@",
            value,
        )

    remaining = sorted(
        set(
            TOKEN_RE.findall(
                result
            )
        )
    )

    if remaining:
        refuse(
            "DPL1.SYSTEMD.UNRESOLVED_TEMPLATE_TOKEN",
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
        "--output-dir",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--on-calendar",
        default="hourly",
    )

    parser.add_argument(
        "--randomized-delay-sec",
        default="5min",
    )

    args = parser.parse_args()

    package = (
        args.package_root.resolve()
    )

    config_path = (
        args.instance_config.resolve()
    )

    output = (
        args.output_dir.resolve(
            strict=False
        )
    )

    if not package.is_dir():
        refuse(
            "DPL1.SYSTEMD.PACKAGE_ROOT_INVALID",
            str(package),
        )

    data = load_config(
        config_path
    )

    service = data.get(
        "service",
        {}
    )

    filesystem = data.get(
        "filesystem",
        {}
    )

    try:

        runtime_root = safe_absolute_path(
            "runtime_root",
            filesystem["runtime_root"],
        )

        python_bin = safe_absolute_path(
            "python_bin",
            service["python_bin"],
        )

        service_user = safe_atom(
            "service_user",
            service["user"],
        )

        service_group = safe_atom(
            "service_group",
            service["group"],
        )

        on_calendar = safe_atom(
            "on_calendar",
            args.on_calendar,
        )

        randomized = safe_atom(
            "randomized_delay_sec",
            args.randomized_delay_sec,
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ) as exc:

        refuse(
            "DPL1.SYSTEMD.CONFIG_INVALID",
            str(exc),
        )

    if not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_.-]*",
        service_user,
    ):
        refuse(
            "DPL1.SYSTEMD.CONFIG_INVALID",
            "service user invalid",
        )

    if not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_.-]*",
        service_group,
    ):
        refuse(
            "DPL1.SYSTEMD.CONFIG_INVALID",
            "service group invalid",
        )

    runtime_entrypoint = (
        package
        / "bin"
        / "ia-security-agent-cycle"
    ).resolve()

    if not runtime_entrypoint.is_file():
        refuse(
            "DPL1.SYSTEMD.RUNTIME_ENTRYPOINT_MISSING",
            str(runtime_entrypoint),
        )

    if (
        not python_bin.is_file()
        or not os.access(
            python_bin,
            os.X_OK,
        )
    ):
        refuse(
            "DPL1.SYSTEMD.CONFIG_INVALID",
            "python binary invalid",
        )

    expected_config = (
        runtime_root
        / "config"
        / "instance-config-v1.json"
    ).resolve()

    if expected_config != config_path:
        refuse(
            "DPL1.SYSTEMD.CONFIG_INVALID",
            "config/runtime binding mismatch",
        )

    if output.exists():
        refuse(
            "DPL1.SYSTEMD.OUTPUT_EXISTS",
            str(output),
        )

    output.mkdir(
        mode=0o750,
        parents=False,
    )

    service_template = (
        package
        / "systemd"
        / "ia-security-agent.service.in"
    )

    timer_template = (
        package
        / "systemd"
        / "ia-security-agent.timer.in"
    )

    if (
        not service_template.is_file()
        or not timer_template.is_file()
    ):
        refuse(
            "DPL1.SYSTEMD.TEMPLATE_MISSING",
            "service or timer template missing",
        )

    values = {
        "PACKAGE_ROOT":
            str(package),

        "RUNTIME_ROOT":
            str(runtime_root),

        "INSTANCE_CONFIG":
            str(config_path),

        "RUNTIME_ENTRYPOINT":
            str(runtime_entrypoint),

        "PYTHON_BIN":
            str(python_bin),

        "SERVICE_USER":
            service_user,

        "SERVICE_GROUP":
            service_group,

        "ON_CALENDAR":
            on_calendar,

        "RANDOMIZED_DELAY_SEC":
            randomized,
    }

    rendered_service = render(
        service_template.read_text(
            encoding="utf-8"
        ),
        values,
    )

    rendered_timer = render(
        timer_template.read_text(
            encoding="utf-8"
        ),
        values,
    )

    service_out = (
        output
        / "ia-security-agent.service"
    )

    timer_out = (
        output
        / "ia-security-agent.timer"
    )

    write_exclusive(
        service_out,
        rendered_service,
    )

    write_exclusive(
        timer_out,
        rendered_timer,
    )

    print(
        json.dumps(
            {
                "schema":
                    "ia-security-agent-stage-result-v1",
                "stage":
                    "SYSTEMD_RENDER",
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

    return EXIT_VALID


if __name__ == "__main__":
    raise SystemExit(main())
