# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief waybackurls output parser for historical endpoint discovery analysis.
#
# This module parses waybackurls output and classifies discovered historical
# URLs by endpoint patterns and archival characteristics. Each finding
# represents a previously observed endpoint that may reveal attack surface
# or stale/orphaned functionality.
#
# Detects:
# - API endpoints from history
# - Sensitive file access patterns
# - Parameter variations across time
# - Potentially removed but historically accessible resources
# - Mixed protocol usage
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Tuple
import re

from main.schema.normalize import Finding


# ---------------------------------------------------------------------
# Pattern Definitions (precompiled for performance)
# ---------------------------------------------------------------------

API_PATTERNS = [re.compile(p) for p in {
    r'/api/', r'/api-', r'/apis/',
    r'/graphql', r'/gql',
    r'/rest/', r'/service',
    r'/v\d+/', r'/v\d+-',
}]

SENSITIVE_FILES = [re.compile(p) for p in {
    r'\.env', r'\.git', r'\.svn',
    r'\.backup', r'\.bak', r'\.old',
    r'backup\.zip', r'backup\.sql',
    r'config\.php', r'settings\.php',
}]

ANOMALY_PATTERNS = [re.compile(p) for p in {
    r'%0A', r'%0D',   # Encoded newlines
    r'\[', r'\]',    # Brackets
    r'\$',           # Variables
}]

PARAM_PATTERNS = {
    "version", "api_version",
    "token", "session",
    "user", "id",
}


# ---------------------------------------------------------------------
# Classification Logic
# ---------------------------------------------------------------------

def _classify_url(url: str) -> Tuple[str, str]:
    """
    Classify historical URL by pattern and assign severity.

    Returns:
        (url_type, severity)
    """
    parsed = urlparse(url)
    path = parsed.path.lower()

    # Suspicious formatting anomalies
    if any(p.search(url) for p in ANOMALY_PATTERNS):
        return ("malformed_url", "medium")

    # Sensitive files
    if any(p.search(path) for p in SENSITIVE_FILES):
        return ("sensitive_file", "critical")

    # API endpoints
    if any(p.search(path) for p in API_PATTERNS):
        return ("api_endpoint", "medium")

    # Parameter significance
    if parsed.query:
        for param in re.findall(r'[?&]([^=&]+)=', parsed.query):
            if param.lower() in PARAM_PATTERNS:
                return ("parameter_variation", "medium")

    return ("historical_endpoint", "low")


def _extract_parameters(url: str) -> dict:
    """
    Extract query parameters into key-value dictionary.
    """
    parsed = urlparse(url)
    params = {}

    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" in pair:
                name, value = pair.split("=", 1)
                params[name] = value

    return params


# ---------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------

def parse_waybackurls(raw_file: Path) -> List[Finding]:
    """
    Parse waybackurls output into normalized path findings.

    waybackurls emits one historical URL per line from Wayback Machine.
    Each URL is validated, normalized, classified, and de-duplicated.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue

            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                continue

            # Normalize: strip fragment only
            normalized_url = parsed._replace(fragment="").geturl()

            url_type, severity = _classify_url(normalized_url)
            params = _extract_parameters(normalized_url)

            if url_type == "sensitive_file":
                title = f"Historical sensitive file: {parsed.path}"
            elif url_type == "api_endpoint":
                title = f"Historical API endpoint: {parsed.path}"
            elif url_type == "parameter_variation":
                title = f"Historical parameter variation: {parsed.path}"
            elif url_type == "malformed_url":
                title = f"Malformed historical URL: {parsed.path}"
            else:
                title = f"Historical endpoint (Wayback): {parsed.path}"

            if normalized_url not in findings:
                findings[normalized_url] = Finding(
                    asset=normalized_url,
                    title=title,
                    tool="waybackurls",
                    kind="path",
                    severity=severity,
                    occurrences=1,
                    timestamp=timestamp,
                    evidence_path=str(raw_file),
                    metadata={
                        "source": "waybackurls",
                        "url_type": url_type,
                        "path": parsed.path,
                        "query": parsed.query,
                        "domain": parsed.netloc,
                        "parameters": params,
                        "scheme": parsed.scheme,
                        "cwe": "CWE-215: Information Exposure Through Debug Information",
                    },
                )
            else:
                findings[normalized_url].occurrences += 1

    # Deterministic output ordering
    return sorted(findings.values(), key=lambda f: f.asset)