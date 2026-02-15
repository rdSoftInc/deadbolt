# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief gau output parser for historical URL enumeration analysis.
#
# This module parses gau output to extract historical URLs from web archives.
# Each URL is analyzed for sensitive path patterns, endpoint types, and
# potential security exposures. Results are normalized into Deadbolt Finding
# objects representing discovered attack surface from archive histories.
#
# Detects:
# - Sensitive file paths (.env, .git, backups, configs)
# - Admin and control panel endpoints
# - API endpoints and integrations
# - Backup and archive files
# - Exposed credential or configuration endpoints
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
# Pattern Definitions
# ---------------------------------------------------------------------

SENSITIVE_FILES = [re.compile(p) for p in {
    r'\.env', r'\.git', r'\.svn', r'\.hg',
    r'\.backup', r'\.bak', r'\.old',
    r'backup\.zip', r'backup\.tar', r'backup\.sql',
    r'\.htaccess', r'web\.config',
    r'config\.php', r'settings\.php', r'database\.php',
    r'private\.key', r'secret\.key',
    r'\.aws', r'credentials'
}]

ADMIN_PATHS = [re.compile(p) for p in {
    r'/admin', r'/adm', r'/administrator',
    r'/manage', r'/manager',
    r'/console', r'/panel',
    r'/dashboard', r'/control',
    r'/backend', r'/staff',
}]

API_PATHS = [re.compile(p) for p in {
    r'/api/', r'/api-',
    r'/v\d+/', r'/v\d+-',
    r'/rest/', r'/rest-',
    r'/graphql', r'/gql',
    r'/rpc/', r'/soap',
    r'/services/'
}]

BACKUP_FILES = [re.compile(p) for p in {
    r'\.zip', r'\.tar', r'\.gz', r'\.rar',
    r'\.sql', r'\.dump',
    r'backup', r'archive', r'export',
    r'\.bak', r'\.old', r'\.previous'
}]

USER_PATHS = [re.compile(p) for p in {
    r'/users', r'/accounts', r'/members',
    r'/credentials', r'/passwords',
    r'/tokens', r'/keys', r'/secrets',
    r'/profile', r'/user-list'
}]

CODE_PATHS = [re.compile(p) for p in {
    r'/src/', r'/source', r'/code',
    r'/debug', r'/test', r'/example',
    r'\.js\.map', r'\.ts\.map',
    r'/webpack', r'/sourcemap'
}]


# ---------------------------------------------------------------------
# Classification Logic
# ---------------------------------------------------------------------

def _classify_url(url: str) -> Tuple[str, str]:
    """
    Classify URL by path pattern and assign severity.

    Returns:
        (url_type, severity)
    """
    path = urlparse(url).path.lower()

    if any(p.search(path) for p in SENSITIVE_FILES):
        return ("sensitive_file", "critical")

    if any(p.search(path) for p in CODE_PATHS):
        return ("source_code", "critical")

    if any(p.search(path) for p in BACKUP_FILES):
        return ("backup_file", "high")

    if any(p.search(path) for p in USER_PATHS):
        return ("user_endpoint", "high")

    if any(p.search(path) for p in ADMIN_PATHS):
        return ("admin_panel", "high")

    if any(p.search(path) for p in API_PATHS):
        return ("api_endpoint", "medium")

    return ("historical_url", "low")


# ---------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------

def parse_gau(raw_file: Path) -> List[Finding]:
    """
    Parse gau output into normalized path findings.

    gau emits one URL per line sourced from historical web archives.
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

            # Normalize (strip fragment only)
            normalized_url = parsed._replace(fragment="").geturl()

            url_type, severity = _classify_url(normalized_url)

            if url_type == "sensitive_file":
                title = f"Sensitive file in archive: {parsed.path}"
            elif url_type == "source_code":
                title = f"Source code/debug path in archive: {parsed.path}"
            elif url_type == "backup_file":
                title = f"Backup file in archive: {parsed.path}"
            elif url_type == "user_endpoint":
                title = f"User/credential endpoint in archive: {parsed.path}"
            elif url_type == "admin_panel":
                title = f"Admin panel in archive: {parsed.path}"
            elif url_type == "api_endpoint":
                title = f"API endpoint in archive: {parsed.path}"
            else:
                title = "Historical URL from archive"

            if normalized_url not in findings:
                findings[normalized_url] = Finding(
                    asset=normalized_url,
                    title=title,
                    tool="gau",
                    kind="path",
                    severity=severity,
                    occurrences=1,
                    timestamp=timestamp,
                    evidence_path=str(raw_file),
                    metadata={
                        "source": "gau",
                        "url_type": url_type,
                        "path": parsed.path,
                        "domain": parsed.netloc,
                        "cwe": "CWE-215: Information Exposure Through Debug Information",
                    },
                )
            else:
                findings[normalized_url].occurrences += 1

    # Deterministic output ordering
    return sorted(findings.values(), key=lambda f: f.asset)