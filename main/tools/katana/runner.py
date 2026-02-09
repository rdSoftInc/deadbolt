# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief katana execution wrapper.
#
# This module defines the execution logic for katana using a containerized
# runtime. katana performs crawling and URL discovery across target assets
# and produces a plain-text list of discovered URLs.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from main.execution.docker import run_container


def run_katana(targets: Path, output: Path):
    """
    Execute katana crawler against target assets.

    Consumes:
      - assets (domains or URLs)

    Produces:
      - paths (discovered URLs, one per line)

    Notes:
      - katana focuses on URL discovery
      - Output is plain text for easy downstream consumption
    """
    run_container(
        image="deadbolt-katana",
        args=[
            "-list", "/targets.txt",
            "-silent",
            "-o", "/output/katana.txt",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )