# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief ffuf execution wrapper.
#
# This module defines the execution logic for ffuf using a containerized
# runtime. ffuf is used for endpoint discovery via host × path fuzzing
# with a deterministic wordlist.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from main.execution.docker import run_container


def run_ffuf(targets: Path, output: Path):
    """
    Execute ffuf for endpoint discovery.

    Consumes:
      - assets (domains or base URLs)

    Produces:
      - paths (JSON output containing discovered endpoints)

    Strategy:
      - Normalize targets to bare hosts
      - Host × path fuzzing
      - No recursion
      - Deterministic wordlist
    """

    # -------------------------------
    # Normalize target hosts
    # -------------------------------
    normalized = output.parent / "ffuf_targets.txt"

    lines = targets.read_text().splitlines()
    hosts = []

    for l in lines:
        l = l.strip()
        if not l:
            continue

        # Strip URL scheme if present
        if l.startswith("http://") or l.startswith("https://"):
            l = l.split("://", 1)[1]

        hosts.append(l)

    normalized.write_text("\n".join(hosts))

    # -------------------------------
    # Wordlist validation
    # -------------------------------
    wordlist = Path("wordlists/common.txt")
    if not wordlist.is_file():
        raise RuntimeError(
            "wordlists/common.txt must exist and be a file (ffuf wordlist missing)"
        )

    # -------------------------------
    # Container execution
    # -------------------------------
    run_container(
        image="deadbolt-ffuf",
        args=[
            "-w", "/wordlists/common.txt",
            "-u", "https://FUZZ",
            "-mc", "200,204,301,302,307,401,403",
            "-of", "json",
            "-o", "/output/ffuf.json",
            "-timeout", "10",
            "-t", "20",
            "-sa",
            "-s",
        ],
        mounts={
            normalized: "/targets.txt",
            output.parent: "/output",
            Path("wordlists/common.txt"): "/wordlists/common.txt",
        },
    )