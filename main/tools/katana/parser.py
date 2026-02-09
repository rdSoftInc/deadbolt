# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief katana output parser.
#
# This module parses raw katana crawler output and normalizes discovered URLs
# into Deadbolt Finding objects of kind "path". Each unique URL represents a
# discovered endpoint obtained via crawling.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone

from main.schema.normalize import Finding


def parse_katana(raw_file: Path):
    """
    Parse katana output into normalized findings.

    katana emits one discovered URL per line. Each unique URL is normalized
    into a Finding of kind "path". Duplicate URLs increment the occurrence
    counter.
    """
    findings = {}
    # key = asset URL, value = Finding

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue

            if url not in findings:
                findings[url] = Finding(
                    asset=url,
                    title="Discovered URL",
                    tool="katana",
                    kind="path",

                    # Web-oriented fields (not applicable here)
                    status_code=None,
                    technologies=[],
                    webserver=None,
                    cdn=None,
                    cdn_name=None,

                    # Vulnerability fields (not applicable)
                    severity=None,
                    template_id=None,

                    occurrences=1,
                    timestamp=datetime.now(timezone.utc),
                    evidence_path=str(raw_file),
                )
            else:
                findings[url].occurrences += 1

    return list(findings.values())