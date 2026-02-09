# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief gau output parser.
#
# This module parses raw gau output and normalizes historical URLs into
# Deadbolt Finding objects. Each unique URL is treated as a discovered path
# originating from third-party web archives.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

from main.schema.normalize import Finding


def parse_gau(raw_file: Path):
    """
    Parse gau output into normalized findings.

    gau emits one URL per line sourced from historical archives such as
    Wayback Machine, Common Crawl, and OTX. Only fully qualified URLs
    (scheme + host) are retained. Duplicate URLs increment the occurrence
    counter.
    """
    findings = {}

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue

            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                continue

            if url not in findings:
                findings[url] = Finding(
                    asset=url,
                    title="Historical URL",
                    tool="gau",
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
                    timestamp=datetime.now(timezone.utc),
                    evidence_path=str(raw_file),
                )
            else:
                findings[url].occurrences += 1

    return list(findings.values())