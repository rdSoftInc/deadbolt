# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief dnsx output parser.
#
# This module parses raw dnsx output and normalizes it into Deadbolt Finding
# objects representing resolvable domains. Each unique domain is treated as
# a discovered asset, with occurrence counts aggregated across the output.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone

from main.schema.normalize import Finding


def parse_dnsx(raw_file: Path):
    """
    Parse dnsx output into normalized findings.

    dnsx produces one resolvable domain per line. Each unique domain is
    normalized into a Finding of kind "asset". Duplicate domains increment
    the occurrence counter.
    """
    findings = {}

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            domain = line.strip()
            if not domain:
                continue

            if domain not in findings:
                findings[domain] = Finding(
                    asset=domain,
                    title="Resolvable domain",
                    tool="dnsx",
                    kind="asset",

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
                findings[domain].occurrences += 1

    return list(findings.values())