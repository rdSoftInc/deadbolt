# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief subfinder output parser for subdomain discovery analysis.
#
# This module parses subfinder output and classifies discovered subdomains
# by patterns indicating service type, sensitivity, and exposure level.
# Each finding represents an asset with security significance assessment.
#
# Detects:
# - API subdomains (api, graphql, grpc, etc.)
# - Documentation subdomains (docs, swagger, api-doc, etc.)
# - Staging/development subdomains (staging, dev, test, etc.)
# - Admin/management subdomains (admin, manage, console, etc.)
# - Wildcard and catch-all subdomains
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple
import re

from main.schema.normalize import Finding


# ---------------------------------------------------------------------
# Pattern Definitions
# ---------------------------------------------------------------------

API_PATTERNS = {
    r'^api\.', r'^api-', r'\.api\.', r'\.api-',
    r'^graphql\.', r'^graphql-',
    r'^grpc\.', r'^grpc-',
    r'^v\d+\.', r'^v\d+-',
    r'^rest\.', r'^rest-',
}

DOCS_PATTERNS = {
    r'^docs\.', r'^docs-',
    r'^doc\.', r'^documentation\.',
    r'^api-docs\.', r'^apidocs\.',
    r'^swagger\.', r'^api-doc\.',
}

STAGING_PATTERNS = {
    r'^staging\.', r'^staging-',
    r'^stage\.', r'^stage-',
    r'^test\.', r'^test-',
    r'^dev\.', r'^dev-',
    r'^internal\.', r'^internal-',
    r'^qa\.', r'^qa-',
    r'^uat\.', r'^uat-',
}

ADMIN_PATTERNS = {
    r'^admin\.', r'^admin-',
    r'^manage\.', r'^manage-',
    r'^console\.', r'^console-',
    r'^panel\.', r'^panel-',
    r'^dashboard\.', r'^dashboard-',
}

WILDCARD_PATTERNS = {
    r'unique\.\d+\.',
    r'random\.',
    r'\*\.',
}


# ---------------------------------------------------------------------
# Classification Helpers
# ---------------------------------------------------------------------

def _classify_subdomain(domain: str) -> Tuple[str, str]:
    """
    Classify subdomain by pattern and assign severity.

    Returns:
        (subdomain_type, severity)
    """
    domain_lower = domain.lower()

    if any(re.search(p, domain_lower) for p in WILDCARD_PATTERNS):
        return ("wildcard", "high")

    if any(re.search(p, domain_lower) for p in API_PATTERNS):
        return ("api", "high")

    if any(re.search(p, domain_lower) for p in DOCS_PATTERNS):
        return ("documentation", "medium")

    if any(re.search(p, domain_lower) for p in STAGING_PATTERNS):
        return ("staging_dev", "medium")

    if any(re.search(p, domain_lower) for p in ADMIN_PATTERNS):
        return ("admin", "high")

    return ("generic", "low")


def _extract_base_domain(fqdn: str) -> str:
    """
    Extract base domain from FQDN.

    Note:
        This is a simplified extractor and does not handle multi-level TLDs
        (e.g., .co.uk). Consider tldextract for full accuracy.
    """
    parts = fqdn.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn


# ---------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------

def parse_subfinder(raw_file: Path) -> List[Finding]:
    """
    Parse subfinder output into classified asset findings.

    subfinder emits one subdomain per line. Each subdomain is normalized,
    classified, de-duplicated, and assigned a severity based on exposure
    heuristics.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            domain = line.strip()
            if not domain:
                continue

            # Normalize
            domain = domain.rstrip(".").lower()

            subdomain_type, severity = _classify_subdomain(domain)
            base_domain = _extract_base_domain(domain)

            if domain not in findings:

                if subdomain_type == "api":
                    title = f"API subdomain discovered: {domain}"
                elif subdomain_type == "documentation":
                    title = f"Documentation subdomain discovered: {domain}"
                elif subdomain_type == "staging_dev":
                    title = f"Staging/Development subdomain discovered: {domain}"
                elif subdomain_type == "admin":
                    title = f"Admin/Control subdomain discovered: {domain}"
                elif subdomain_type == "wildcard":
                    title = f"Wildcard/Catch-all subdomain: {domain}"
                else:
                    title = f"Subdomain discovered: {domain}"

                findings[domain] = Finding(
                    asset=domain,
                    title=title,
                    tool="subfinder",
                    kind="asset",
                    severity=severity,
                    occurrences=1,
                    timestamp=timestamp,
                    evidence_path=str(raw_file),
                    metadata={
                        "source": "subfinder",
                        "subdomain_type": subdomain_type,
                        "base_domain": base_domain,
                        "cwe": "CWE-215: Information Exposure Through Debug Information",
                    },
                )
            else:
                findings[domain].occurrences += 1

    # Deterministic ordering
    return sorted(findings.values(), key=lambda f: f.asset)