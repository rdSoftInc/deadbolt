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
from urllib.parse import urlsplit, urlunsplit
from main.execution.docker import run_container
from main.tools.ffuf.constants import (
    FFUF_IMAGE,
    FFUF_WORDLIST_HOST_PATH,
    FFUF_WORDLIST_CONTAINER_PATH,
    FFUF_OUTPUT_NAME,
)
from main.domains.web.profiles import WebScanProfile, capped_rate, policy_for


def run_ffuf(targets: Path, output: Path, *, profile: WebScanProfile | str = WebScanProfile.STANDARD, rate_limit: float | None = None) -> None:
    """
    Execute ffuf for endpoint discovery.

    Consumes:
        - assets (domains or base URLs)

    Produces:
        - paths (JSON output containing discovered endpoints)

    Execution Model:
        BASE URL × WORDLIST fuzzing using:
            - /targets.txt as BASE
            - configured shallow wordlist as FUZZ
            - BASE/FUZZ target template
    """

    # -----------------------------------------------------------------
    # Normalize base URLs while preserving scheme, port, and base path.
    # -----------------------------------------------------------------

    normalized = output.parent / "ffuf_targets.txt"

    raw_lines = targets.read_text(encoding="utf-8").splitlines()
    base_urls = []

    for line in raw_lines:
        line = line.strip()
        if not line:
            continue

        if not line.startswith(("http://", "https://")):
            line = f"https://{line}"
        parsed = urlsplit(line)
        if not parsed.netloc:
            continue
        path = parsed.path.rstrip("/")
        base_urls.append(urlunsplit((parsed.scheme, parsed.netloc, path, "", "")))

    if not base_urls:
        raise RuntimeError("ffuf received empty asset list")

    normalized.write_text(
        "\n".join(sorted(set(base_urls))),
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

    policy = policy_for(profile)
    run_container(
        image=FFUF_IMAGE,
        args=[
            # Base URL wordlist
            "-w", "/targets.txt:BASE",

            # Path wordlist
            "-w", f"{FFUF_WORDLIST_CONTAINER_PATH}:FUZZ",

            # Target template
            "-u", "BASE/FUZZ",

            # Calibrate generic/SPA fallback responses to reduce false paths.
            "-ac",

            # Match relevant status codes only
            "-mc", "200,204,301,302,307,401,403",

            # Output configuration
            "-of", "json",
            "-o", f"/output/{FFUF_OUTPUT_NAME}",

            # Performance & stability tuning
            "-timeout", str(policy.ffuf_timeout),
            "-t", str(policy.ffuf_threads),
            "-rate", str(capped_rate(policy.httpx_rate, rate_limit)),

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
