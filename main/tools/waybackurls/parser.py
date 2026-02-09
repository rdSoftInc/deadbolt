# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief waybackurls output parser.
#
# This module parses raw waybackurls output and normalizes historical URLs
# into Deadbolt Finding objects. Each finding represents a previously observed
# endpoint collected from archival sources.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from typing import List

from main.schema.normalize import Finding


def parse_waybackurls(raw_file: Path) -> List[Finding]:
    """
    Parse waybackurls output into normalized findings.

    waybackurls emits one historical URL per line. Each unique URL is
    normalized into a Finding of kind "path". Duplicate URLs increment
    the occurrence counter.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue

            if url not in findings:
                findings[url] = Finding(
                    asset=url,
                    title="Historical endpoint (Wayback)",
                    tool="waybackurls",
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