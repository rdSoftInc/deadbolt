# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief ffuf output parser.
#
# This module parses ffuf JSON output and normalizes discovered endpoints
# into Deadbolt Finding objects of kind "path". Each unique URL is treated
# as a discovered endpoint, with duplicate hits aggregated via an occurrence
# counter.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List

from main.schema.normalize import Finding


def parse_ffuf(raw_file: Path) -> List[Finding]:
    """
    Parse ffuf JSON output into normalized findings.

    ffuf emits a JSON document containing a list of fuzzing results. Each
    result with a valid URL is normalized into a Finding of kind "path".
    Duplicate URLs increment the occurrence counter.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    data = json.loads(raw_file.read_text(encoding="utf-8"))

    for r in data.get("results", []):
        url = r.get("url")
        if not url:
            continue

        if url not in findings:
            findings[url] = Finding(
                asset=url,
                title="Discovered endpoint (ffuf)",
                tool="ffuf",
                kind="path",

                status_code=r.get("status"),
                technologies=[],
                webserver=None,
                cdn=None,
                cdn_name=None,

                severity=None,
                template_id=None,
                occurrences=1,

                timestamp=timestamp,
                evidence_path=str(raw_file),
            )
        else:
            findings[url].occurrences += 1

    return list(findings.values())