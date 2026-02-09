# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief paramspider output parser.
#
# This module parses paramspider output and normalizes discovered parameterized
# URLs into Deadbolt Finding objects. Each finding represents an input surface
# expansion rather than a vulnerability.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from typing import List

from main.schema.normalize import Finding


def parse_paramspider(raw_file: Path) -> List[Finding]:
    """
    Parse paramspider output into normalized findings.

    paramspider emits URLs containing query parameters. Each unique URL
    is normalized into a Finding of kind "path". Duplicate entries
    increment the occurrence counter.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    for line in raw_file.read_text(encoding="utf-8").splitlines():
        url = line.strip()
        if not url:
            continue

        if url not in findings:
            findings[url] = Finding(
                asset=url,
                title="Discovered parameter (paramspider)",
                tool="paramspider",
                kind="path",

                # Web-oriented fields (not applicable)
                status_code=None,
                technologies=[],
                webserver=None,
                cdn=None,
                cdn_name=None,

                # Vulnerability fields (not applicable)
                severity=None,
                template_id=None,

                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
            )
        else:
            findings[url].occurrences += 1

    return list(findings.values())