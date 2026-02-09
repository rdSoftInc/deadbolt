# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief nuclei execution wrapper.
#
# This module defines the execution logic for nuclei using a containerized
# runtime. nuclei performs vulnerability scanning using template-based
# detection and produces newline-delimited JSON output.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from main.execution.docker import run_container


def run_nuclei(targets: Path, output: Path, min_severity: str = "medium"):
    """
    Execute nuclei against target assets.

    Consumes:
      - assets (domains or URLs)

    Produces:
      - findings (JSONL vulnerability matches)

    Parameters:
      - min_severity: minimum severity threshold passed to nuclei
        (filtering occurs at scan time, not parse time)

    Notes:
      - nuclei is the primary vulnerability detection engine
      - Severity filtering here reduces noise early in the pipeline
    """
    run_container(
        image="deadbolt-nuclei",
        args=[
            "-l", "/targets.txt",
            "-jsonl",
            "-severity", min_severity,
            "-o", "/output/nuclei.jsonl",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )