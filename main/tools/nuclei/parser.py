# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief Parsers for httpx and nuclei JSONL outputs.
#
# This module normalizes JSONL output produced by httpx and nuclei into
# Deadbolt Finding objects. httpx provides service validation and enrichment,
# while nuclei produces vulnerability findings with severity semantics.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import json
from pathlib import Path
from datetime import datetime, timezone

from main.schema.normalize import Finding


def parse_httpx(raw_file: Path):
    """
    Parse httpx JSONL output into findings.

    httpx emits one JSON object per line describing a live HTTP service.
    Each entry is normalized into a Finding representing a reachable
    HTTP endpoint with associated metadata.

    Note:
      - Findings produced here are enrichment signals, not vulnerabilities.
      - This parser intentionally performs minimal interpretation.
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


def parse_nuclei(raw_file: Path):
    """
    Parse nuclei JSONL output into vulnerability findings.

    nuclei emits one JSON object per line per match. Findings are
    de-duplicated by (asset, template_id), with occurrences counted
    and the highest observed severity retained.

    This parser represents the authoritative vulnerability signal
    within Deadbolt.
    """

    SEVERITY_ORDER = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    findings = {}  # (asset, template_id) -> Finding

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            data = json.loads(line)

            asset = (
                data.get("host")
                or data.get("matched")
                or data.get("url")
            )
            template_id = data.get("template-id")

            if not asset or not template_id:
                continue

            title = data.get("info", {}).get("name", "Nuclei Finding")
            severity = data.get("info", {}).get("severity", "info")

            key = (asset, template_id)

            if key not in findings:
                finding = Finding(
                    asset=asset,
                    title=title,
                    tool="nuclei",
                    kind="finding",

                    severity=severity,
                    template_id=template_id,
                    timestamp=datetime.now(timezone.utc),
                    evidence_path=str(raw_file),
                )

                # Dynamic attribute (permitted by Pydantic model)
                finding.occurrences = 1
                findings[key] = finding

            else:
                existing = findings[key]
                existing.occurrences += 1

                # Preserve highest observed severity
                if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(
                    existing.severity or "info", 0
                ):
                    existing.severity = severity
                    existing.title = title

    return list(findings.values())