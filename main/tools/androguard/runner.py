# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief Androguard execution wrapper for Android static analysis.
#
# This module executes selected Androguard subcommands to extract
# deterministic, machine-consumable Android metadata such as:
# - Package identity (apkid)
# - AndroidManifest.xml (axml)
# - Signing and certificate information (sign)
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import subprocess
import json


def _run(cmd: list[str]) -> str:
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout.strip()


def run_androguard(apk: Path, output: Path) -> None:
    """
    Execute Androguard against an Android APK.

    Output:
    - androguard.json: structured aggregation of androguard subcommand outputs
    """

    data = {}

    data["apkid"] = _run([
        "docker", "run", "--rm",
        "-v", f"{apk.resolve()}:/input.apk",
        "deadbolt-androguard",
        "apkid",
        "/input.apk",
    ])

    data["axml"] = _run([
        "docker", "run", "--rm",
        "-v", f"{apk.resolve()}:/input.apk",
        "deadbolt-androguard",
        "axml",
        "/input.apk",
    ])

    data["sign"] = _run([
        "docker", "run", "--rm",
        "-v", f"{apk.resolve()}:/input.apk",
        "deadbolt-androguard",
        "sign",
        "/input.apk",
    ])

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")