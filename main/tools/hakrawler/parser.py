# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief hakrawler output parser for client-side path enumeration analysis.
#
# This module parses raw hakrawler output and classifies discovered URLs
# by security-relevant path patterns. Each URL is normalized, analyzed,
# and converted into a Deadbolt path artifact.
#
# Detects:
# - API endpoints and integrations
# - Admin and control panel paths
# - Sensitive file endpoints (.env, .git, backups, etc.)
# - Authentication and user endpoints
# - Debug and development paths
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
# Precompiled Patterns
# ---------------------------------------------------------------------

SENSITIVE_FILES = [
    re.compile(p) for p in {
        r"\.env", r"\.env\.local", r"\.env\.production",
        r"\.git/", r"\.svn/", r"\.hg/",
        r"\.backup", r"\.bak", r"\.old",
        r"backup\.zip", r"backup\.tar", r"backup\.sql",
        r"\.htaccess", r"web\.config",
        r"config\.php", r"settings\.php", r"database\.php",
        r"private\.key", r"secret\.key", r"id_rsa",
        r"\.aws", r"credentials", r"\.docker"
    }
]

API_PATHS = [
    re.compile(p) for p in {
        r"/api/", r"/api-", r"/apis/",
        r"/graphql", r"/gql", r"/relay",
        r"/rest/", r"/rest-",
        r"/v\d+/", r"/v\d+-",
        r"/service/", r"/services/",
        r"/rpc/", r"/rpc-",
        r"/soap", r"/webservice"
    }
]

ADMIN_PATHS = [
    re.compile(p) for p in {
        r"/admin", r"/adm", r"/administrator",
        r"/manage", r"/management",
        r"/console", r"/panel",
        r"/dashboard", r"/dash",
        r"/control", r"/cp",
        r"/backend", r"/staff",
        r"/moderator"
    }
]

AUTH_PATHS = [
    re.compile(p) for p in {
        r"/auth", r"/authentication",
        r"/login", r"/signin", r"/sign-in",
        r"/register", r"/signup", r"/sign-up",
        r"/user", r"/users", r"/accounts", r"/account",
        r"/profile", r"/me",
        r"/oauth", r"/openid", r"/saml"
    }
]

BACKUP_PATHS = [
    re.compile(p) for p in {
        r"backup", r"archive", r"export",
        r"download", r"import",
        r"\.zip", r"\.tar", r"\.gz", r"\.rar",
        r"\.sql", r"\.dump", r"\.sql\.gz"
    }
]

DEBUG_PATHS = [
    re.compile(p) for p in {
        r"/debug", r"/debugger",
        r"/test", r"/tests",
        r"/example", r"/examples",
        r"/dev", r"/development",
        r"/staging", r"/stage",
        r"/src/", r"/source",
        r"\.js\.map", r"\.ts\.map",
        r"/webpack", r"/sourcemap"
    }
]


# ---------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------

def _classify_path(path: str) -> Tuple[str, str]:
    """
    Classify URL path and assign severity.

    Returns:
        (path_type, severity)
    """
    if any(p.search(path) for p in SENSITIVE_FILES):
        return ("sensitive_file", "critical")

    if any(p.search(path) for p in DEBUG_PATHS):
        return ("debug_source", "critical")

    if any(p.search(path) for p in BACKUP_PATHS):
        return ("backup_archive", "high")

    if any(p.search(path) for p in ADMIN_PATHS):
        return ("admin_panel", "high")

    if any(p.search(path) for p in AUTH_PATHS):
        return ("auth_endpoint", "medium")

    if any(p.search(path) for p in API_PATHS):
        return ("api_endpoint", "medium")

    return ("other_path", "low")


# ---------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------

def parse_hakrawler(raw_file: Path) -> List[Finding]:
    """
    Parse hakrawler output into normalized path findings.

    hakrawler emits one URL per line discovered via client-side crawling.
    Each URL is normalized, classified, deduplicated, and enriched with
    metadata before being returned as Deadbolt Finding objects.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    for line in raw_file.read_text(encoding="utf-8").splitlines():
        raw_url = line.strip()
        if not raw_url:
            continue

        parsed = urlparse(raw_url)

        if not parsed.scheme or not parsed.netloc:
            continue

        # Normalize URL (strip fragment)
        normalized = parsed._replace(fragment="").geturl()
        path = parsed.path.lower()

        path_type, severity = _classify_path(path)

        if path_type == "sensitive_file":
            title = f"Sensitive file discovered: {parsed.path}"
        elif path_type == "debug_source":
            title = f"Debug/source path discovered: {parsed.path}"
        elif path_type == "backup_archive":
            title = f"Backup/archive path discovered: {parsed.path}"
        elif path_type == "admin_panel":
            title = f"Admin panel path discovered: {parsed.path}"
        elif path_type == "auth_endpoint":
            title = f"Authentication endpoint discovered: {parsed.path}"
        elif path_type == "api_endpoint":
            title = f"API endpoint discovered: {parsed.path}"
        else:
            title = f"Path discovered: {parsed.path}"

        if normalized not in findings:
            findings[normalized] = Finding(
                asset=normalized,
                title=title,
                tool="hakrawler",
                kind="path",
                severity=severity,
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata={
                    "source": "hakrawler",
                    "path_type": path_type,
                    "path": parsed.path,
                    "query": parsed.query,
                    "domain": parsed.netloc,
                    "scheme": parsed.scheme,
                    "cwe": "CWE-215: Information Exposure Through Debug Information",
                },
            )
        else:
            findings[normalized].occurrences += 1

    # Deterministic ordering (resume-safe)
    return sorted(findings.values(), key=lambda f: f.asset)