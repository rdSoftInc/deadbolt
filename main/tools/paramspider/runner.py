# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief paramspider execution wrapper.
#
# This module defines the execution logic for paramspider using a containerized
# runtime. paramspider discovers query parameters associated with target URLs
# and outputs parameterized endpoints.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import subprocess
import tempfile


def run_paramspider(targets: Path, output: Path):
    """
    Execute paramspider for parameter discovery.

    Consumes:
      - assets (URLs only)

    Produces:
      - paths (URLs containing discovered parameters)

    Notes:
      - Targets without a URL scheme are ignored
      - Execution is performed per URL to avoid cross-contamination
    """

    # -------------------------------
    # Filter valid URL targets
    # -------------------------------
    urls = [
        l.strip()
        for l in targets.read_text(encoding="utf-8").splitlines()
        if l.startswith("http://") or l.startswith("https://")
    ]

    if not urls:
        output.write_text("")
        return

    results = []

    # -------------------------------
    # Per-URL execution
    # -------------------------------
    for url in urls:
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{tmp}:/output",
                    "deadbolt-paramspider",
                    "-d", url,
                    "-o", "/output",
                ],
                capture_output=True,
                text=True,
            )

            if proc.returncode != 0:
                continue

            for line in proc.stdout.splitlines():
                if "=" in line:
                    results.append(line.strip())

    # -------------------------------
    # Deduplicate and persist output
    # -------------------------------
    output.write_text(
        "\n".join(sorted(set(results))),
        encoding="utf-8",
    )