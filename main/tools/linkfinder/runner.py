# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief LinkFinder execution wrapper for JavaScript endpoint discovery.
#
# This module executes LinkFinder against JavaScript resources discovered
# from validated web assets. It extracts embedded endpoints and writes
# structured JSON output for downstream processing.
#
# Strategy:
# - Retrieve JavaScript files from target assets
# - Execute LinkFinder inside Docker
# - Aggregate extracted endpoints
# - Persist normalized JSON output
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import subprocess
import json
import re
from typing import Set


JS_PATTERN = re.compile(r"\.js($|\?)", re.IGNORECASE)


def _is_js_url(url: str) -> bool:
    """Determine whether a URL points to a JavaScript resource."""
    return bool(JS_PATTERN.search(url))


def run_linkfinder(assets_file: Path, output: Path):
    """
    Execute LinkFinder against JavaScript URLs derived from assets.

    Consumes:
      - assets file (validated HTTP URLs)

    Produces:
      - JSON output containing extracted endpoint paths
    """

    endpoints: Set[str] = set()

    assets = [
        line.strip()
        for line in assets_file.read_text().splitlines()
        if line.strip()
    ]

    js_targets = [a for a in assets if _is_js_url(a)]

    if not js_targets:
        output.write_text(json.dumps({"endpoints": []}, indent=2))
        return

    for js_url in js_targets:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "deadbolt-linkfinder",
                "-i", js_url,
                "-o", "cli"
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            continue

        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("/"):
                endpoints.add(line)

    output.write_text(
        json.dumps({"endpoints": sorted(endpoints)}, indent=2),
        encoding="utf-8",
    )