# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file container.py
# @brief Docker container execution helper.
#
# This module provides a thin wrapper around `docker run` used to execute
# tool containers in a controlled and reproducible manner. It is responsible
# for assembling the container invocation, mounting required volumes, and
# propagating execution failures with useful diagnostics.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import subprocess
from pathlib import Path
from typing import Dict, List, Optional


def run_container(
    *,
    image: str,
    args: List[str],
    mounts: Dict[Path, str],
    entrypoint: Optional[str] = None,
):
    """
    Execute a Docker container with mounted volumes.

    This helper constructs and executes a `docker run` command using the
    provided image, arguments, and host-to-container volume mappings.
    Execution output is captured, and failures are raised as runtime errors
    with full stdout and stderr context.

    At least one volume mount is required to ensure deterministic input
    and output handling.
    """
    if not mounts:
        raise ValueError("run_container() requires at least one volume mount")

    cmd = ["docker", "run", "--rm"]

    # Register host-to-container volume mounts
    for host, container in mounts.items():
        cmd += ["-v", f"{host.resolve()}:{container}"]

    # Optional entrypoint override
    if entrypoint:
        cmd += ["--entrypoint", entrypoint]

    # Image and arguments
    cmd.append(image)
    cmd.extend(args)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Docker failed\n"
            f"STDERR:\n{result.stderr}\n"
            f"STDOUT:\n{result.stdout}"
        )