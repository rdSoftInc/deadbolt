# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief gau execution wrapper.
#
# This module defines the execution logic for gau using a containerized
# runtime. gau enumerates historical URLs associated with target domains
# by querying multiple public web archives.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from main.execution.docker import run_container


def run_gau(targets: Path, output: Path):
    """
    Execute gau against target domains.

    Consumes:
      - assets (domains)

    Produces:
      - paths (historical URLs, one per line)

    Data sources:
      - Wayback Machine
      - Common Crawl
      - AlienVault OTX
    """
    run_container(
        image="deadbolt-gau",
        args=[
            "--providers", "wayback,commoncrawl,otx",
            "--subs",
            "--o", "/output/gau.txt",
            "/targets.txt",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )