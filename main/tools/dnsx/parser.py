# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief dnsx output parser for DNS enumeration analysis.
#
# This module parses dnsx output to extract and classify resolvable domains
# and subdomains. Each domain is analyzed for exposure patterns and normalized
# into Deadbolt Finding objects representing discovered attack surface assets.
#
# Detects:
# - API subdomains (api, graphql, grpc, v1, v2, etc.)
# - Documentation subdomains (docs, swagger, openapi, etc.)
# - Staging/development domains (staging, dev, test, internal, etc.)
# - Administrative/control panel domains (admin, console, portal, etc.)
# - Wildcard / catch-all DNS patterns
#
# NOTE:
# Base domain extraction is intentionally simplified and does not handle
# multi-level public suffixes (e.g., example.co.uk). For full correctness,
# consider integrating tldextract.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple, Dict
import json
import re

from main.schema.normalize import Finding


# -----------------------------------------------------------------------------
# Compiled Pattern Definitions
# -----------------------------------------------------------------------------

API_PATTERNS = [
    re.compile(p) for p in (
        r'^api\.', r'^api-',
        r'\.api\.', r'\.api-',
        r'^graphql\.', r'^graphql-',
        r'^grpc\.', r'^grpc-',
        r'^v\d+\.', r'^v\d+-',
    )
]

DOCS_PATTERNS = [
    re.compile(p) for p in (
        r'^docs\.', r'^docs-',
        r'^documentation\.', r'^doc\.',
        r'^swagger\.', r'^api-docs\.',
        r'^apidocs\.', r'^redoc\.',
        r'^openapi\.',
    )
]

STAGING_PATTERNS = [
    re.compile(p) for p in (
        r'^staging\.', r'^staging-', r'-staging\.', r'-staging-',
        r'^stage\.', r'^stage-',
        r'^test\.', r'^test-', r'-test\.', r'-test-',
        r'^dev\.', r'^dev-', r'-dev\.', r'-dev-',
        r'^internal\.', r'^internal-',
        r'^qa\.', r'^qa-',
        r'^uat\.', r'^uat-',
        r'^preview\.', r'^preview-',
    )
]

ADMIN_PATTERNS = [
    re.compile(p) for p in (
        r'^admin\.', r'^admin-',
        r'^manage\.', r'^manage-',
        r'^console\.', r'^console-',
        r'^portal\.', r'^portal-',
        r'^dashboard\.', r'^dashboard-',
        r'^control\.', r'^control-',
        r'^panel\.',
    )
]

WILDCARD_PATTERNS = [
    re.compile(p) for p in (
        r'unique\.\d+\.',
        r'random\.',
        r'\*\.',
    )
]


# -----------------------------------------------------------------------------
# Classification Logic
# -----------------------------------------------------------------------------

def _classify_subdomain(domain: str) -> Tuple[str, str, str]:
    """
    Classify subdomain based on exposure patterns.

    Returns:
        (subdomain_type, severity, confidence)
    """

    d = domain.lower()

    if any(p.search(d) for p in WILDCARD_PATTERNS):
        return ("wildcard", "high", "high")

    if any(p.search(d) for p in API_PATTERNS):
        return ("api", "high", "high")

    if any(p.search(d) for p in DOCS_PATTERNS):
        return ("documentation", "medium", "high")

    if any(p.search(d) for p in STAGING_PATTERNS):
        return ("staging_dev", "medium", "high")

    if any(p.search(d) for p in ADMIN_PATTERNS):
        return ("admin", "high", "high")

    return ("subdomain", "low", "medium")


def _extract_base_domain(fqdn: str) -> str:
    """
    Extract base domain from FQDN (simplified).
    Does not support multi-level public suffixes.
    """

    parts = fqdn.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn


def _is_valid_domain(domain: str) -> bool:
    """
    Basic validation to filter malformed dnsx lines.
    """

    if "." not in domain:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    if " " in domain:
        return False

    return True


# -----------------------------------------------------------------------------
# Main Parser
# -----------------------------------------------------------------------------

def parse_dnsx(raw_file: Path) -> List[Finding]:
    """
    Parse dnsx output into normalized asset findings.

    dnsx emits one resolvable domain per line.
    Each unique domain is classified and normalized into
    kind="asset" findings to align with Deadbolt's
    artifact-driven web enumeration model.
    """

    findings: Dict[Tuple[str, str], Finding] = {}
    timestamp = datetime.now(timezone.utc)

    def add_finding(domain: str,
                    title: str,
                    severity: str,
                    metadata: Dict):

        key = (domain, title)

        if key not in findings:
            findings[key] = Finding(
                asset=domain,
                title=title,
                tool="dnsx",
                kind="asset",
                severity=severity,
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata=metadata,
            )
        else:
            findings[key].occurrences += 1

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                record = {}
            domain = str(record.get("host") or record.get("input") or raw).strip().lower()
            if not domain:
                continue

            if not _is_valid_domain(domain):
                continue

            subdomain_type, severity, confidence = _classify_subdomain(domain)
            base_domain = _extract_base_domain(domain)

            if subdomain_type == "api":
                title = f"API subdomain discovered: {domain}"
            elif subdomain_type == "documentation":
                title = f"Documentation subdomain discovered: {domain}"
            elif subdomain_type == "staging_dev":
                title = f"Staging/Development domain discovered: {domain}"
            elif subdomain_type == "admin":
                title = f"Admin/Control panel discovered: {domain}"
            elif subdomain_type == "wildcard":
                title = f"Wildcard/Catch-all subdomain: {domain}"
            else:
                title = f"Subdomain discovered: {domain}"

            add_finding(
                domain,
                title,
                severity,
                {
                    "source": "dnsx",
                    "subdomain_type": subdomain_type,
                    "base_domain": base_domain,
                    "confidence": confidence,
                    "a": record.get("a", []),
                    "aaaa": record.get("aaaa", []),
                    "cname": record.get("cname", []),
                },
            )

    # Deterministic ordering
    return sorted(findings.values(), key=lambda f: (f.asset, f.title))
