# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief graphql-cop output parser.
#
# This module parses graphql-cop output and normalizes discovered GraphQL
# endpoints and operations into Deadbolt Finding objects. Each finding
# represents a potential GraphQL exposure surface.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from typing import List

from main.schema.normalize import Finding


def parse_graphql_cop(raw_file: Path) -> List[Finding]:
    """
    Parse graphql-cop output into normalized findings.

    graphql-cop emits lines in the format:
        <endpoint> :: <detail>

    Each unique (endpoint, detail) pair is normalized into a Finding of
    kind "path". Duplicate entries increment the occurrence counter.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    for line in raw_file.read_text(encoding="utf-8").splitlines():
        if "::" not in line:
            continue

        endpoint, detail = line.split("::", 1)
        endpoint = endpoint.strip()
        detail = detail.strip()

        key = f"{endpoint}:{detail}"

        if key not in findings:
            findings[key] = Finding(
                asset=endpoint,
                title=f"GraphQL exposure: {detail}",
                tool="graphql-cop",
                kind="path",

                # Web-oriented fields
                status_code=None,
                technologies=["graphql"],
                webserver=None,
                cdn=None,
                cdn_name=None,

                # Vulnerability fields (not applicable here)
                severity=None,
                template_id=None,

                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
            )
        else:
            findings[key].occurrences += 1

    return list(findings.values())