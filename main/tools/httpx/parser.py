# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief httpx output parser.
#
# This module parses newline-delimited JSON output from httpx and normalizes
# live HTTP services into Deadbolt Finding objects. httpx acts as an
# enrichment and validation layer, attaching HTTP metadata to discovered
# assets or paths.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import json
from datetime import datetime, timezone

from main.schema.normalize import Finding


def parse_httpx(raw_file: Path):
    """
    Parse httpx JSONL output into normalized findings.

    httpx emits one JSON object per line describing a live HTTP service.
    Each entry is normalized into a Finding. The resulting findings may
    represent validated assets or enriched paths depending on the
    execution context.
    """
    findings = []

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            data = json.loads(line)

            url = data.get("url")
            if not url:
                continue

            findings.append(
                Finding(
                    asset=url,
                    title=data.get("title") or "Live HTTP Service",
                    tool="httpx",
                    kind="finding",

                    status_code=data.get("status_code"),
                    technologies=data.get("tech") or [],
                    webserver=data.get("webserver"),
                    cdn=data.get("cdn"),
                    cdn_name=data.get("cdn_name"),

                    timestamp=datetime.now(timezone.utc),
                    evidence_path=str(raw_file),
                )
            )

    return findings