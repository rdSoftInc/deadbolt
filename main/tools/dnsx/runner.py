# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief dnsx execution wrapper.
#
# This module defines the execution logic for dnsx using a containerized
# runtime. dnsx resolves domains and outputs only those that successfully
# resolve via DNS.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from main.execution.docker import run_container


def run_dnsx(targets: Path, output: Path):
    """
    Execute dnsx against a list of target domains.

    Input:
    - targets: text file containing domains (one per line)

    Output:
    - dnsx.txt: one resolvable domain per line

    The tool is executed inside a container, with input and output paths
    mounted explicitly to ensure deterministic behavior.
    """
    run_container(
        image="deadbolt-dnsx",
        args=[
            "-l", "/targets.txt",
            "-silent",
            "-o", "/output/dnsx.txt",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )