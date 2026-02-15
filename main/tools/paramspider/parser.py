# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief paramspider output parser for parameter discovery analysis.
#
# This module parses paramspider output and classifies discovered parameterized
# URLs by parameter significance and endpoint type. Each finding represents
# an input surface expansion with potential attack vectors.
#
# Detects:
# - Sensitive parameter names (auth, token, api_key, etc.)
# - Potentially exploitable parameters (redirect, file, cmd, id, etc.)
# - API endpoints with parameters
# - Admin/control paths with parameters
# - Authentication endpoints with parameters
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
from typing import List, Tuple
import re

from main.schema.normalize import Finding


# ---------------------------------------------------------------------
# Parameter Classification Sets
# ---------------------------------------------------------------------

SENSITIVE_PARAMS = {
    "auth", "token", "api_key", "apikey", "secret",
    "password", "passwd", "pwd",
    "access_token", "refresh_token",
    "session", "sid", "cookie",
    "credential", "credentials",
    "key", "keys",
}

EXPLOIT_PARAMS = {
    "url", "redirect", "return", "next",
    "file", "path", "dir", "page",
    "query", "search", "q",
    "id", "uid", "user_id",
    "cmd", "command", "exec",
}

API_PATTERNS = [
    re.compile(p) for p in {
        r"/api/", r"/api-", r"/apis/",
        r"/graphql", r"/gql",
        r"/rest/", r"/service",
        r"/v\d+/", r"/v\d+-",
    }
]

ADMIN_PATTERNS = [
    re.compile(p) for p in {
        r"/admin", r"/manage", r"/console", r"/dashboard"
    }
]

AUTH_PATTERNS = [
    re.compile(p) for p in {
        r"/auth", r"/login", r"/register", r"/oauth"
    }
]


# ---------------------------------------------------------------------
# Parameter Analysis
# ---------------------------------------------------------------------

def _analyze_parameters(url: str) -> Tuple[List[str], List[str], bool]:
    """
    Analyze query parameters for sensitivity and exploitability.

    Returns:
        (sensitive_params, exploit_params, has_sensitive)
    """
    parsed = urlparse(url)

    if not parsed.query:
        return [], [], False

    params = parse_qs(parsed.query, keep_blank_values=True)

    sensitive = []
    exploit = []

    for name in params.keys():
        lower = name.lower()

        if any(keyword in lower for keyword in SENSITIVE_PARAMS):
            sensitive.append(name)

        if any(keyword in lower for keyword in EXPLOIT_PARAMS):
            exploit.append(name)

    return sensitive, exploit, bool(sensitive)


def _classify_endpoint(url: str) -> Tuple[str, str]:
    """
    Classify endpoint type and assign baseline severity.

    Returns:
        (endpoint_type, severity)
    """
    path = urlparse(url).path.lower()

    if any(p.search(path) for p in API_PATTERNS):
        return ("api_endpoint", "medium")

    if any(p.search(path) for p in ADMIN_PATTERNS):
        return ("admin_endpoint", "high")

    if any(p.search(path) for p in AUTH_PATTERNS):
        return ("auth_endpoint", "high")

    return ("generic_endpoint", "low")


# ---------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------

def parse_paramspider(raw_file: Path) -> List[Finding]:
    """
    Parse paramspider output into normalized path findings.

    paramspider emits URLs containing query parameters. Each URL is
    normalized, classified, and de-duplicated before being returned
    as Deadbolt Finding objects.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    for line in raw_file.read_text(encoding="utf-8").splitlines():
        url = line.strip()
        if not url:
            continue

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue

        # Normalize URL (strip fragment only)
        normalized_url = parsed._replace(fragment="").geturl()

        sensitive_params, exploit_params, has_sensitive = _analyze_parameters(normalized_url)
        endpoint_type, endpoint_severity = _classify_endpoint(normalized_url)

        # Severity determination hierarchy
        if has_sensitive:
            severity = "high"
            title = f"Sensitive parameter discovered: {parsed.path}"
        elif exploit_params:
            severity = "medium"
            title = f"Exploitable parameter discovered: {parsed.path}"
        elif endpoint_type == "admin_endpoint":
            severity = "high"
            title = f"Admin parameter discovered: {parsed.path}"
        elif endpoint_type == "auth_endpoint":
            severity = "high"
            title = f"Authentication parameter discovered: {parsed.path}"
        elif endpoint_type == "api_endpoint":
            severity = "medium"
            title = f"API parameter discovered: {parsed.path}"
        else:
            severity = "low"
            title = f"Parameter discovered: {parsed.path}"

        if normalized_url not in findings:
            findings[normalized_url] = Finding(
                asset=normalized_url,
                title=title,
                tool="paramspider",
                kind="path",
                severity=severity,
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata={
                    "source": "paramspider",
                    "endpoint_type": endpoint_type,
                    "path": parsed.path,
                    "query": parsed.query,
                    "domain": parsed.netloc,
                    "sensitive_params": sensitive_params,
                    "exploit_params": exploit_params,
                    "has_sensitive_params": has_sensitive,
                    "cwe": "CWE-200: Information Exposure",
                },
            )
        else:
            findings[normalized_url].occurrences += 1

    # Deterministic ordering for stable resume/state behavior
    return sorted(findings.values(), key=lambda f: f.asset)