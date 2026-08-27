# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief subfinder execution wrapper.
#
# This module defines the execution logic for subfinder using a containerized
# runtime. subfinder performs passive subdomain enumeration and outputs
# discovered subdomains as plain text.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from main.execution.docker import run_container
from main.core.tool_manifest import get_tool_config


def run_subfinder(targets: Path, output: Path):
    """
    Execute subfinder against target domains.

    Consumes:
      - targets (root domains)

    Produces:
      - assets (discovered subdomains)

    Notes:
      - subfinder is a passive enumeration tool
      - Output is one subdomain per line
    """
    run_container(
        image=get_tool_config("subfinder").image,
        args=[
            "-dL", "/targets.txt",
            "-silent",
            "-o", "/output/subfinder.txt",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )
