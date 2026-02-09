# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief httpx execution wrapper.
#
# This module defines the execution logic for httpx using a containerized
# runtime. httpx validates targets by probing for live HTTP services and
# produces structured JSON output for enrichment.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from main.execution.docker import run_container


def run_httpx(targets: Path, output: Path):
    """
    Execute httpx against target assets or paths.

    Consumes:
      - targets (domains, URLs, or paths)

    Produces:
      - findings (newline-delimited JSON describing live HTTP services)

    Notes:
      - httpx does not perform crawling
      - It validates reachability and enriches targets with HTTP metadata
    """
    run_container(
        image="deadbolt-httpx",
        args=[
            "-l", "/targets.txt",
            "-json",
            "-o", "/output/httpx.json",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )