# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief subfinder output parser.
#
# This module parses raw subfinder output and normalizes discovered subdomains
# into Deadbolt Finding objects. Each finding represents a newly discovered
# asset within the target scope.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone

from main.schema.normalize import Finding


def parse_subfinder(raw_file: Path):
    """
    Parse subfinder output into normalized findings.

    subfinder emits one subdomain per line. Each unique subdomain is
    normalized into a Finding of kind "asset". Duplicate entries
    increment the occurrence counter.
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
                    title="Discovered subdomain",
                    tool="subfinder",
                    kind="asset",

                    # Web-oriented fields (not applicable at discovery stage)
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