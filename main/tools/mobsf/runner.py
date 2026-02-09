# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief MobSF execution and orchestration logic.
#
# This module manages the lifecycle of a MobSF container, uploads an Android
# APK, triggers static analysis, and retrieves the resulting JSON report.
# It is responsible for container reuse, readiness detection, and API
# interaction.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import subprocess
import time
import requests
import json
import re


MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
MOBSF_PORT = 8000
STARTUP_TIMEOUT = 300

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")


# -------------------------
# Logging helper
# -------------------------

def log(msg: str):
    """Emit MobSF-related log output."""
    print(f"[mobsf] {msg}", flush=True)


# -------------------------
# Docker helpers
# -------------------------

def _find_running_mobsf() -> str | None:
    """
    Return the container ID of a running MobSF instance, if any.
    """
    cid = subprocess.check_output(
        [
            "docker", "ps",
            "--filter", f"ancestor={MOBSF_IMAGE}",
            "--format", "{{.ID}}",
        ],
        text=True,
    ).strip()
    return cid or None


def _start_container() -> str:
    """
    Start a MobSF container or reuse an existing one.
    """
    cid = _find_running_mobsf()
    if cid:
        log(f"Reusing existing MobSF container: {cid}")
        return cid

    log("Starting new MobSF container")
    return subprocess.check_output(
        [
            "docker", "run",
            "-d",
            "--rm",
            "-p", f"{MOBSF_PORT}:8000",
            MOBSF_IMAGE,
        ],
        text=True,
    ).strip()


# -------------------------
# MobSF readiness + API key
# -------------------------

def _extract_api_key(cid: str) -> str:
    """
    Extract the MobSF REST API key from container logs.
    """
    deadline = time.time() + STARTUP_TIMEOUT

    while time.time() < deadline:
        logs = subprocess.check_output(
            ["docker", "logs", cid],
            text=True,
            stderr=subprocess.STDOUT,
        )

        clean_logs = ANSI_ESCAPE_RE.sub("", logs)

        match = re.search(
            r"REST\s+API\s+Key:\s*([a-f0-9]{64})",
            clean_logs,
            re.IGNORECASE,
        )

        if match:
            return match.group(1)

        time.sleep(2)

    raise RuntimeError("Failed to extract MobSF API key from container logs")


def _wait_for_api_ready(api_key: str) -> None:
    """
    Wait until the MobSF REST API becomes responsive.
    """
    headers = {"X-Mobsf-Api-Key": api_key}
    start = time.time()

    while time.time() - start < STARTUP_TIMEOUT:
        try:
            r = requests.get(
                "http://127.0.0.1:8000/api/v1/scans",
                headers=headers,
                timeout=5,
            )
            if r.status_code == 200:
                return
        except requests.RequestException:
            pass

        time.sleep(2)

    raise RuntimeError("MobSF API did not become ready")


# -------------------------
# Main scan logic
# -------------------------

def run_mobsf(apk: Path, output: Path) -> None:
    """
    Execute a MobSF static analysis scan against an Android APK.

    Consumes:
      - apk (Android application package)

    Produces:
      - JSON report containing static analysis results
    """
    log("Starting MobSF")

    cid = _start_container()
    log(f"Using container: {cid}")

    api_key = _extract_api_key(cid)
    log(f"Extracted API key: {api_key[:8]}...")

    _wait_for_api_ready(api_key)
    log("MobSF API is ready")

    headers = {"X-Mobsf-Api-Key": api_key}

    # Upload APK
    log(f"Uploading APK: {apk} ({apk.stat().st_size} bytes)")
    with apk.open("rb") as f:
        r = requests.post(
            "http://127.0.0.1:8000/api/v1/upload",
            headers=headers,
            files={
                "file": (
                    apk.name,
                    f,
                    "application/vnd.android.package-archive",
                )
            },
            timeout=120,
        )

    r.raise_for_status()
    scan_hash = r.json()["hash"]
    log(f"Scan hash: {scan_hash}")

    # Start scan
    log("Starting scan")
    try:
        r = requests.post(
            "http://127.0.0.1:8000/api/v1/scan",
            headers=headers,
            data={"hash": scan_hash},
            timeout=180,
        )
        r.raise_for_status()
    except requests.exceptions.ReadTimeout:
        log("Scan request timed out — assuming scan started")

    # Poll until report is available
    log("Waiting for report to become available")
    deadline = time.time() + STARTUP_TIMEOUT
    last_err = None

    while time.time() < deadline:
        try:
            r = requests.post(
                "http://127.0.0.1:8000/api/v1/report_json",
                headers=headers,
                data={"hash": scan_hash},
                timeout=30,
            )

            if r.status_code == 200:
                report = r.json()
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps(report, indent=2))
                log(f"Report written to {output}")
                return

            last_err = f"{r.status_code}: {r.text}"

        except requests.RequestException as e:
            last_err = str(e)

        time.sleep(5)

    raise RuntimeError(
        f"Timed out waiting for report_json. Last error: {last_err}"
    )