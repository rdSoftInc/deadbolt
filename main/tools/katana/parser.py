# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief katana output parser for headless browser crawling analysis.
#
# This module parses raw katana crawler output and classifies discovered URLs
# by path patterns, parameter significance, crawl depth, and dynamic identifiers.
#
# Detects:
# - API endpoints and integrations
# - Management/admin paths
# - Dynamic resource identifiers (UUIDs, numeric IDs)
# - Sensitive query parameters
# - HTTP usage
# - Crawl depth and path nesting
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
from typing import Tuple, List
import re

from main.schema.normalize import Finding


# ---------------------------------------------------------------------
# Precompiled Patterns
# ---------------------------------------------------------------------

SENSITIVE_PARAMS = {
    "auth", "token", "secret", "key", "password", "passwd", "pwd",
    "api_key", "apikey", "access_token", "refresh_token",
    "session", "sid", "cookie",
    "credential", "credentials",
}

API_PATTERNS = [
    re.compile(p) for p in {
        r"/api/", r"/apis/", r"/api-",
        r"/graphql", r"/gql",
        r"/rest/", r"/service",
        r"/v\d+/", r"/v\d+-",
    }
]

ADMIN_PATTERNS = [
    re.compile(p) for p in {
        r"/admin", r"/manage", r"/console",
        r"/dashboard", r"/panel",
        r"/control", r"/settings",
    }
]

DYNAMIC_PATTERNS = [
    re.compile(r"/[a-f0-9]{8,}"),
    re.compile(r"/\d{6,}"),
    re.compile(r"/[a-zA-Z0-9]{10,}"),
]


# ---------------------------------------------------------------------
# Classification Helpers
# ---------------------------------------------------------------------

def _classify_path(path: str) -> Tuple[str, str]:
    """
    Classify path pattern and assign baseline severity.

    Returns:
        (path_type, severity)
    """
    if any(p.search(path) for p in ADMIN_PATTERNS):
        return ("admin_management", "high")

    if any(p.search(path) for p in API_PATTERNS):
        return ("api_endpoint", "medium")

    if any(p.search(path) for p in DYNAMIC_PATTERNS):
        return ("dynamic_identifier", "medium")

    return ("discovered_url", "low")


def _analyze_parameters(query: str) -> Tuple[List[str], bool]:
    """
    Analyze query parameters for sensitivity.
    """
    if not query:
        return [], False

    params = parse_qs(query, keep_blank_values=True)
    sensitive = []

    for name in params.keys():
        lower = name.lower()
        if any(keyword in lower for keyword in SENSITIVE_PARAMS):
            sensitive.append(name)

    return sensitive, bool(sensitive)


def _calculate_depth(path: str) -> int:
    """
    Calculate URL depth based on path segments.
    """
    return len([s for s in path.split("/") if s])


# ---------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------

def parse_katana(raw_file: Path) -> List[Finding]:
    """
    Parse katana crawler output into normalized path findings.

    katana emits one URL per line discovered via headless browser crawling.
    Each URL is normalized, classified, deduplicated, and enriched with
    crawl metadata before being returned as Deadbolt Finding objects.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            raw_url = line.strip()
            if not raw_url:
                continue

            parsed = urlparse(raw_url)

            if not parsed.scheme or not parsed.netloc:
                continue

            # Normalize URL (strip fragment)
            normalized = parsed._replace(fragment="").geturl()

            path = parsed.path.lower()
            query = parsed.query

            path_type, baseline_severity = _classify_path(path)
            sensitive_params, has_sensitive = _analyze_parameters(query)
            depth = _calculate_depth(path)

            # Severity refinement
            if has_sensitive:
                severity = "high"
                title = f"URL with sensitive parameters: {parsed.path}"
            elif path_type == "admin_management":
                severity = "high"
                title = f"Admin/management path discovered: {parsed.path}"
            elif path_type == "api_endpoint":
                severity = "medium"
                title = f"API endpoint discovered: {parsed.path}"
            elif path_type == "dynamic_identifier":
                severity = "medium"
                title = f"Dynamic resource path discovered: {parsed.path}"
            else:
                severity = baseline_severity
                title = f"Path discovered: {parsed.path}"

            # Flag HTTP usage
            if parsed.scheme == "http":
                severity = "medium" if severity == "low" else severity
                title += " [HTTP]"

            if normalized not in findings:
                findings[normalized] = Finding(
                    asset=normalized,
                    title=title,
                    tool="katana",
                    kind="path",
                    severity=severity,
                    occurrences=1,
                    timestamp=timestamp,
                    evidence_path=str(raw_file),
                    metadata={
                        "source": "katana",
                        "path_type": path_type,
                        "path": parsed.path,
                        "query": query,
                        "domain": parsed.netloc,
                        "scheme": parsed.scheme,
                        "depth": depth,
                        "sensitive_params": sensitive_params,
                        "has_sensitive_params": has_sensitive,
                        "cwe": "CWE-215: Information Exposure Through Debug Information",
                    },
                )
            else:
                findings[normalized].occurrences += 1

    # Deterministic ordering for resume stability
    return sorted(findings.values(), key=lambda f: f.asset)