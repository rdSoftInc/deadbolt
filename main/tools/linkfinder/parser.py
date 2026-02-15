# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief LinkFinder output parser for web enumeration.
#
# This module parses structured JSON output produced by LinkFinder and
# normalizes extracted endpoints into Deadbolt path artifacts.
#
# Filtering Strategy:
# - Reject protocol-relative URLs (e.g., //cdn.example.com)
# - Reject static asset files (.css, .ico, .png, etc.)
# - Reject high-entropy hash-like paths (likely build artifacts)
# - Emit only meaningful relative endpoints beginning with "/"
#
# LinkFinder is enumeration-only and does not assign severity.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict

from main.schema.normalize import Finding


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Static asset extensions that should not be promoted to path artifacts
STATIC_EXTENSIONS = (
    ".css", ".js", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
)

# High-entropy single-segment paths (e.g., hashed bundle references)
HASH_LIKE = re.compile(r"^[a-zA-Z0-9]{16,}$")


# -----------------------------------------------------------------------------
# Validation Helpers
# -----------------------------------------------------------------------------

def _is_valid_endpoint(path: str) -> bool:
    """
    Determine whether an extracted endpoint should be promoted
    to a Deadbolt path artifact.

    Validation rules:
    - Must be a string
    - Must begin with "/"
    - Must not be protocol-relative
    - Must not point to static assets
    - Must not be a single high-entropy hash-like segment
    """

    if not isinstance(path, str):
        return False

    candidate = path.strip()

    if not candidate:
        return False

    # Reject protocol-relative URLs
    if candidate.startswith("//"):
        return False

    # Only allow relative endpoints
    if not candidate.startswith("/"):
        return False

    # Strip query string for structural analysis
    base = candidate.split("?", 1)[0]

    # Reject static assets
    if base.lower().endswith(STATIC_EXTENSIONS):
        return False

    # Reject high-entropy single-segment paths
    segments = [s for s in base.split("/") if s]
    if len(segments) == 1 and HASH_LIKE.fullmatch(segments[0]):
        return False

    return True


# -----------------------------------------------------------------------------
# Main Parser
# -----------------------------------------------------------------------------

def parse_linkfinder(raw_file: Path) -> List[Finding]:
    """
    Parse LinkFinder JSON output into normalized Deadbolt path artifacts.

    The parser:
    - Filters endpoints using strict validation rules
    - Deduplicates results
    - Emits deterministic output ordering
    """

    timestamp = datetime.now(timezone.utc)
    findings: Dict[str, Finding] = {}

    try:
        data = json.loads(raw_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError):
        return []

    endpoints = data.get("endpoints", [])

    for endpoint in sorted(set(endpoints)):

        if not _is_valid_endpoint(endpoint):
            continue

        if endpoint not in findings:
            findings[endpoint] = Finding(
                asset=endpoint,
                title="JavaScript-discovered endpoint",
                tool="linkfinder",
                kind="path",
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata={
                    "source": "linkfinder",
                    "type": "js_extracted_endpoint",
                    "filtered": True,
                },
            )
        else:
            findings[endpoint].occurrences += 1

    # Deterministic ordering for resume stability
    return sorted(findings.values(), key=lambda f: f.asset)