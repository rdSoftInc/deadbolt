# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief waybackurls execution wrapper.
#
# This module defines the execution logic for waybackurls using a containerized
# runtime. waybackurls performs historical URL discovery based on domain names
# and retrieves endpoints from archival sources such as the Wayback Machine.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from urllib.parse import urlparse
from main.execution.docker import run_container


def _normalize_domains(input_file: Path) -> Path:
    """
    Extract bare domain names from a mixed asset list.

    Input may contain domains or full URLs. All values are normalized
    to lowercase hostnames to ensure correct waybackurls execution.
    """
    domains = set()

    with input_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            if "://" in line:
                parsed = urlparse(line)
                host = parsed.hostname
            else:
                host = line

            if host:
                domains.add(host.lower())

    out = input_file.parent / "wayback_domains.txt"
    out.write_text(
        "\n".join(sorted(domains)) + "\n",
        encoding="utf-8",
    )
    return out


def run_waybackurls(targets: Path, output: Path):
    """
    Execute waybackurls for historical URL discovery.

    Consumes:
      - assets (mixed domains and URLs)

    Produces:
      - paths (historical endpoints)

    Strategy:
      - Normalize all inputs to bare domains
      - Pipe domains into waybackurls via shell entrypoint
      - Capture plain-text URL output
    """
    domains_file = _normalize_domains(targets)

    run_container(
        image="deadbolt-waybackurls",
        entrypoint="sh",
        args=[
            "-c",
            f"cat /input/domains.txt | waybackurls > /output/{output.name}",
        ],
        mounts={
            domains_file: "/input/domains.txt",
            output.parent: "/output",
        },
    )