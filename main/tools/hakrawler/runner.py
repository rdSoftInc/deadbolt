# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief hakrawler execution wrapper.
#
# This module defines the execution logic for hakrawler using a containerized
# runtime. hakrawler performs client-side crawling and requires fully
# qualified URLs as input.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import subprocess


def run_hakrawler(targets: Path, output: Path):
    """
    Execute hakrawler for client-side path discovery.

    Consumes:
      - assets (URLs only; scheme required)

    Produces:
      - paths (discovered client-side URLs)

    Notes:
      - Targets without a URL scheme are ignored
      - No crawling occurs if no valid URLs are provided
    """

    # -------------------------------
    # Filter valid URL targets
    # -------------------------------
    urls = []
    for line in targets.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)

    if not urls:
        # Nothing to crawl → clean skip
        output.write_text("")
        return

    # -------------------------------
    # Container execution (stdin-fed)
    # -------------------------------
    proc = subprocess.run(
        ["docker", "run", "--rm", "-i", "deadbolt-hakrawler"],
        input="\n".join(urls),
        text=True,
        capture_output=True,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"hakrawler failed\nSTDERR:\n{proc.stderr}"
        )

    output.write_text(proc.stdout, encoding="utf-8")