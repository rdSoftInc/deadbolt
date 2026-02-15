# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief ffuf output parser for web fuzzing enumeration analysis.
#
# This module parses ffuf JSON output to extract discovered endpoints
# from directory and file fuzzing. Endpoints are classified by path
# semantics and HTTP response behavior and normalized into Deadbolt
# path artifacts.
#
# Detects:
# - Accessible endpoints (200 responses)
# - Authentication/authorization-protected endpoints (401, 403)
# - Redirected endpoints (301, 302, 307)
# - Sensitive files (.env, .git, backups, configs, etc.)
# - Administrative and internal interfaces
#
# NOTE:
# ffuf is an enumeration tool. Severity modeling is conservative and
# reflects exposure risk — not confirmed vulnerability.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Tuple
from urllib.parse import urlparse

from main.schema.normalize import Finding


# -----------------------------------------------------------------------------
# Precompiled Path Pattern Definitions
# -----------------------------------------------------------------------------

API_PATHS = [
    re.compile(p) for p in (
        r"/api/", r"/api-", r"/apis/",
        r"/v\d+/", r"/v\d+-",
        r"/graphql", r"/gql",
        r"/rest/", r"/rpc/",
    )
]

ADMIN_PATHS = [
    re.compile(p) for p in (
        r"/admin/", r"/admin-",
        r"/manage/", r"/console/",
        r"/panel/", r"/dashboard/",
        r"/control/",
    )
]

AUTH_PATHS = [
    re.compile(p) for p in (
        r"/auth/", r"/login", r"/signin",
        r"/register", r"/signup",
        r"/oauth", r"/openid", r"/saml",
    )
]

INTERNAL_PATHS = [
    re.compile(p) for p in (
        r"/internal/", r"/private/", r"/local/",
    )
]

SENSITIVE_PATHS = [
    re.compile(p) for p in (
        r"/\.env", r"/\.git", r"/\.svn",
        r"/backup", r"/database",
        r"/config", r"/secret",
        r"/credential",
    )
]


# -----------------------------------------------------------------------------
# Classification Helpers
# -----------------------------------------------------------------------------

def _classify_path(path: str) -> Tuple[str, str]:
    """
    Classify endpoint path by exposure semantics.

    Returns:
        (path_type, baseline_severity)
    """

    p = path.lower()

    if any(r.search(p) for r in SENSITIVE_PATHS):
        return ("sensitive_file", "high")

    if any(r.search(p) for r in INTERNAL_PATHS):
        return ("internal", "medium")

    if any(r.search(p) for r in ADMIN_PATHS):
        return ("admin", "medium")

    if any(r.search(p) for r in API_PATHS):
        return ("api", "medium")

    if any(r.search(p) for r in AUTH_PATHS):
        return ("authentication", "low")

    return ("generic", "low")


def _classify_status(
    status: int,
    path_type: str,
    original_domain: str,
    redirect_domain: str | None,
) -> Tuple[str, str]:
    """
    Evaluate HTTP status significance.

    Returns:
        (status_label, severity_adjustment)
    """

    # -------------------------
    # Successful responses
    # -------------------------
    if status in (200, 204):

        if path_type == "sensitive_file":
            return ("accessible_sensitive", "critical")

        if path_type in ("admin", "internal"):
            return ("accessible_restricted", "high")

        if path_type == "api":
            return ("accessible_api", "medium")

        return ("accessible", "low")

    # -------------------------
    # Redirects
    # -------------------------
    if status in (301, 302, 307):

        # Internal redirect = interesting
        if redirect_domain and redirect_domain == original_domain:
            return ("internal_redirect", "low")

        # External redirect = low signal
        return ("external_redirect", "low")

    # -------------------------
    # Auth-protected surfaces
    # -------------------------
    if status in (401, 403):

        if path_type in ("admin", "internal", "api"):
            return ("protected_restricted", "medium")

        return ("authentication_required", "low")

    return ("other", "low")


def _max_severity(a: str, b: str) -> str:
    """
    Return the maximum severity between two severity levels.
    """

    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    reverse = {v: k for k, v in order.items()}

    return reverse[max(order.get(a, 0), order.get(b, 0))]


# -----------------------------------------------------------------------------
# Main Parser
# -----------------------------------------------------------------------------

def parse_ffuf(raw_file: Path) -> List[Finding]:
    """
    Parse ffuf JSON output into normalized path artifacts.

    Each unique (URL, status) pair is classified, deduplicated,
    and emitted as a path artifact for downstream enrichment
    (e.g., httpx → nuclei).

    Deterministic ordering ensures resume-safe pipeline behavior.
    """

    findings: Dict[Tuple[str, int], Finding] = {}
    timestamp = datetime.now(timezone.utc)

    try:
        data = json.loads(raw_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError):
        return []

    for result in data.get("results", []):

        url = result.get("url")
        status = result.get("status")
        location = result.get("redirectlocation")

        if not url or not isinstance(status, int):
            continue

        if status not in (200, 204, 301, 302, 307, 401, 403):
            continue

        parsed = urlparse(url)
        path = parsed.path or "/"

        redirect_domain = None
        if isinstance(location, str):
            redirect_parsed = urlparse(location)
            redirect_domain = redirect_parsed.netloc

        path_type, path_sev = _classify_path(path)

        status_label, status_sev = _classify_status(
            status,
            path_type,
            parsed.netloc,
            redirect_domain,
        )

        final_severity = _max_severity(path_sev, status_sev)

        key = (url, status)

        if key not in findings:

            findings[key] = Finding(
                asset=url,
                title=f"Discovered endpoint: {url} (HTTP {status})",
                tool="ffuf",
                kind="path",
                status_code=status,
                severity=final_severity,
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata={
                    "source": "ffuf",
                    "path_type": path_type,
                    "status_label": status_label,
                    "redirect_domain": redirect_domain,
                },
            )

        else:
            findings[key].occurrences += 1

    return sorted(
        findings.values(),
        key=lambda f: (f.asset, f.status_code or 0),
    )