# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief ffuf execution wrapper.
#
# This module defines the execution logic for ffuf using a containerized
# runtime. ffuf performs host × path fuzzing using a deterministic wordlist
# to discover exposed endpoints.
#
# Strategy:
#   - Normalize input assets to bare hosts
#   - Perform host × path fuzzing using a deterministic shallow wordlist
#   - Restrict matches to security-relevant status codes
#   - Emit deterministic JSON output
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from main.execution.docker import run_container
from main.tools.ffuf.constants import (
    FFUF_IMAGE,
    FFUF_WORDLIST_HOST_PATH,
    FFUF_WORDLIST_CONTAINER_PATH,
    FFUF_OUTPUT_NAME,
)


def run_ffuf(targets: Path, output: Path) -> None:
    """
    Execute ffuf for endpoint discovery.

    Consumes:
        - assets (domains or base URLs)

    Produces:
        - paths (JSON output containing discovered endpoints)

    Execution Model:
        HOST × WORDLIST fuzzing using:
            - /targets.txt as HOST
            - configured shallow wordlist as FUZZ
            - https://HOST/FUZZ target template
    """

    # -----------------------------------------------------------------
    # Normalize target hosts (strip scheme and trailing slashes)
    # -----------------------------------------------------------------

    normalized = output.parent / "ffuf_targets.txt"

    raw_lines = targets.read_text(encoding="utf-8").splitlines()
    hosts = []

    for line in raw_lines:
        line = line.strip()
        if not line:
            continue

        # Strip URL scheme if present
        if line.startswith(("http://", "https://")):
            line = line.split("://", 1)[1]

        # Remove trailing slash
        line = line.rstrip("/")

        if line:
            hosts.append(line)

    if not hosts:
        raise RuntimeError("ffuf received empty asset list")

    normalized.write_text(
        "\n".join(sorted(set(hosts))),
        encoding="utf-8",
    )

    # -----------------------------------------------------------------
    # Validate deterministic wordlist (single source of truth)
    # -----------------------------------------------------------------

    if not FFUF_WORDLIST_HOST_PATH.is_file():
        raise RuntimeError(
            f"{FFUF_WORDLIST_HOST_PATH} must exist "
            "(ffuf wordlist missing)"
        )

    # -----------------------------------------------------------------
    # Execute ffuf (HOST × PATH fuzzing)
    # -----------------------------------------------------------------

    run_container(
        image=FFUF_IMAGE,
        args=[
            # Host wordlist
            "-w", "/targets.txt:HOST",

            # Path wordlist
            "-w", f"{FFUF_WORDLIST_CONTAINER_PATH}:FUZZ",

            # Target template
            "-u", "https://HOST/FUZZ",

            # Match relevant status codes only
            "-mc", "200,204,301,302,307,401,403",

            # Output configuration
            "-of", "json",
            "-o", f"/output/{FFUF_OUTPUT_NAME}",

            # Performance & stability tuning
            "-timeout", "10",
            "-t", "20",

            # Silent mode
            "-sa",
            "-s",
        ],
        mounts={
            normalized: "/targets.txt",
            output.parent: "/output",
            FFUF_WORDLIST_HOST_PATH: FFUF_WORDLIST_CONTAINER_PATH,
        },
    )