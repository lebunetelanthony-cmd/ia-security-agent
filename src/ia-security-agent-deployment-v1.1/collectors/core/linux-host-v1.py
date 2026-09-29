#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any


SCHEMA = "ia-security-agent-linux-host-observation-v1"


def command(
    argv: list[str],
    *,
    timeout: int = 30,
) -> dict[str, Any]:

    binary = shutil.which(argv[0])

    if binary is None:
        return {
            "status": "UNAVAILABLE",
            "command": argv[0],
        }

    env = {
        "PATH": os.environ.get(
            "PATH",
            "/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        "LC_ALL": "C",
        "LANG": "C",
    }

    try:
        proc = subprocess.run(
            [binary, *argv[1:]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
            check=False,
        )
    except Exception as exc:
        return {
            "status": "ERROR",
            "command": argv[0],
            "error_type": type(exc).__name__,
        }

    result: dict[str, Any] = {
        "status": (
            "OK"
            if proc.returncode == 0
            else "ERROR"
        ),
        "returncode": proc.returncode,
    }

    if proc.stderr.strip():
        result["stderr"] = (
            proc.stderr.strip().splitlines()[:20]
        )

    result["stdout"] = proc.stdout

    return result


def os_release() -> dict[str, str]:

    path = Path("/etc/os-release")

    result: dict[str, str] = {}

    if not path.is_file():
        return result

    for raw in path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():

        if (
            not raw
            or raw.startswith("#")
            or "=" not in raw
        ):
            continue

        key, value = raw.split("=", 1)

        result[key] = (
            value.strip()
            .strip('"')
            .strip("'")
        )

    return {
        key: result[key]
        for key in sorted(result)
        if key in {
            "ID",
            "ID_LIKE",
            "NAME",
            "VERSION",
            "VERSION_ID",
            "VERSION_CODENAME",
        }
    }


def packages() -> dict[str, Any]:

    result = command(
        [
            "dpkg-query",
            "-W",
            "-f=${binary:Package}\\t${Version}\\t${Architecture}\\n",
        ],
        timeout=60,
    )

    if result["status"] != "OK":
        result.pop("stdout", None)
        return result

    entries = []

    for line in result["stdout"].splitlines():

        parts = line.split("\t")

        if len(parts) != 3:
            continue

        name, version, arch = parts

        entries.append(
            {
                "name": name,
                "version": version,
                "architecture": arch,
            }
        )

    entries.sort(
        key=lambda x: (
            x["name"],
            x["architecture"],
            x["version"],
        )
    )

    return {
        "status": "OK",
        "count": len(entries),
        "items": entries,
    }


def services() -> dict[str, Any]:

    units = command(
        [
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "--no-pager",
        ]
    )

    running = command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--no-pager",
        ]
    )

    unit_files = []

    if units["status"] == "OK":

        for line in units["stdout"].splitlines():

            parts = line.split()

            if len(parts) >= 2:
                unit_files.append(
                    {
                        "unit": parts[0],
                        "state": parts[1],
                    }
                )

        unit_files.sort(
            key=lambda x: x["unit"]
        )

    running_units = []

    if running["status"] == "OK":

        for line in running["stdout"].splitlines():

            parts = line.split()

            if parts:
                running_units.append(
                    parts[0]
                )

        running_units = sorted(
            set(running_units)
        )

    return {
        "unit_files_status":
            units["status"],
        "running_status":
            running["status"],
        "unit_files":
            unit_files,
        "running":
            running_units,
    }


def network() -> dict[str, Any]:

    interfaces_result = command(
        [
            "ip",
            "-j",
            "address",
            "show",
        ]
    )

    interfaces = []

    if interfaces_result["status"] == "OK":

        try:
            raw = json.loads(
                interfaces_result["stdout"]
            )

            for item in raw:

                addresses = []

                for addr in item.get(
                    "addr_info",
                    [],
                ):

                    addresses.append(
                        {
                            "family":
                                addr.get("family"),
                            "local":
                                addr.get("local"),
                            "prefixlen":
                                addr.get("prefixlen"),
                            "scope":
                                addr.get("scope"),
                        }
                    )

                addresses.sort(
                    key=lambda x: (
                        str(x.get("family")),
                        str(x.get("local")),
                        str(x.get("prefixlen")),
                    )
                )

                interfaces.append(
                    {
                        "ifname":
                            item.get("ifname"),
                        "operstate":
                            item.get("operstate"),
                        "mtu":
                            item.get("mtu"),
                        "address":
                            item.get("address"),
                        "addr_info":
                            addresses,
                    }
                )

            interfaces.sort(
                key=lambda x:
                    str(x.get("ifname"))
            )

        except Exception:
            interfaces_result["status"] = (
                "PARSE_ERROR"
            )

    listeners_result = command(
        [
            "ss",
            "-H",
            "-lntu",
        ]
    )

    listeners = []

    if listeners_result["status"] == "OK":

        for line in (
            listeners_result["stdout"]
            .splitlines()
        ):
            normalized = " ".join(
                line.split()
            )

            if normalized:
                listeners.append(normalized)

        listeners = sorted(
            set(listeners)
        )

    return {
        "interfaces_status":
            interfaces_result["status"],
        "interfaces":
            interfaces,
        "listeners_status":
            listeners_result["status"],
        "listeners":
            listeners,
    }


def mounts() -> dict[str, Any]:

    result = command(
        [
            "findmnt",
            "-J",
            "-o",
            "TARGET,SOURCE,FSTYPE,OPTIONS",
        ]
    )

    if result["status"] != "OK":
        result.pop("stdout", None)
        return result

    try:
        data = json.loads(
            result["stdout"]
        )
    except Exception:
        return {
            "status": "PARSE_ERROR",
        }

    filesystems = []

    def walk(items: list[dict[str, Any]]) -> None:

        for item in items:

            filesystems.append(
                {
                    "target":
                        item.get("target"),
                    "source":
                        item.get("source"),
                    "fstype":
                        item.get("fstype"),
                    "options":
                        item.get("options"),
                }
            )

            children = item.get(
                "children"
            )

            if isinstance(children, list):
                walk(children)

    root_items = data.get("filesystems")

    if isinstance(root_items, list):
        walk(root_items)

    filesystems.sort(
        key=lambda x:
            str(x.get("target"))
    )

    return {
        "status": "OK",
        "items": filesystems,
    }


def collect() -> dict[str, Any]:

    uname = platform.uname()

    payload = {
        "identity": {
            "hostname":
                socket.gethostname(),
            "fqdn":
                socket.getfqdn(),
            "machine":
                uname.machine,
        },

        "os": os_release(),

        "kernel": {
            "system":
                uname.system,
            "release":
                uname.release,
            "version":
                uname.version,
            "machine":
                uname.machine,
        },

        "packages": packages(),

        "services": services(),

        "network": network(),

        "mounts": mounts(),
    }

    return {
        "schema": SCHEMA,
        "collector_version": "1",
        "payload": payload,
    }


if __name__ == "__main__":

    print(
        json.dumps(
            collect(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    )
