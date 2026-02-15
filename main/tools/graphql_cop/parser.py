# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief graphql-cop output parser for GraphQL security assessment.
#
# This module parses graphql-cop output to identify GraphQL endpoints and
# classify exposure types. Each endpoint is normalized and converted into
# Deadbolt path findings suitable for enrichment and vulnerability scanning.
#
# Detects:
# - Introspection exposure
# - Unauthenticated GraphQL access
# - Sensitive field exposure
# - Mutation capabilities
# - Subscription capabilities
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple
from urllib.parse import urlparse
import re

from main.schema.normalize import Finding


# ---------------------------------------------------------------------
# Precompiled Pattern Definitions
# ---------------------------------------------------------------------

INTROSPECTION_PATTERNS = [
    re.compile(p) for p in {
        r"introspection", r"__schema", r"__type",
        r"schema.*query", r"query.*schema"
    }
]

MUTATION_PATTERNS = [
    re.compile(p) for p in {
        r"mutation", r"create", r"update",
        r"delete", r"insert", r"modify"
    }
]

SUBSCRIPTION_PATTERNS = [
    re.compile(p) for p in {
        r"subscription", r"stream",
        r"real.?time", r"watch"
    }
]

SENSITIVE_FIELD_PATTERNS = [
    re.compile(p) for p in {
        r"password", r"token", r"api.?key",
        r"secret", r"credential", r"private.?key",
        r"ssn", r"credit.?card", r"email"
    }
]

AUTH_PATTERNS = [
    re.compile(p) for p in {
        r"unauthorized", r"unauthenticated",
        r"no.?auth", r"public.*endpoint", r"anonymous"
    }
]


# ---------------------------------------------------------------------
# CWE Mapping
# ---------------------------------------------------------------------

def _get_cwe_for_exposure(exposure_type: str) -> str:
    cwe_map = {
        "unauthenticated": "CWE-306: Missing Authentication Check",
        "introspection": "CWE-215: Information Exposure Through Debug Information",
        "sensitive_fields": "CWE-359: Exposure of Private Information",
        "mutations": "CWE-862: Missing Authorization Check",
        "subscriptions": "CWE-359: Exposure of Private Information",
    }
    return cwe_map.get(exposure_type, "CWE-215: Information Exposure")


# ---------------------------------------------------------------------
# Exposure Classification
# ---------------------------------------------------------------------

def _classify_graphql_exposure(detail: str) -> Tuple[str, str, str]:
    """
    Classify GraphQL exposure detail.

    Returns:
        (exposure_type, severity, confidence)
    """
    text = detail.lower()

    if any(p.search(text) for p in AUTH_PATTERNS):
        return ("unauthenticated", "critical", "high")

    if any(p.search(text) for p in INTROSPECTION_PATTERNS):
        return ("introspection", "high", "high")

    if any(p.search(text) for p in SENSITIVE_FIELD_PATTERNS):
        return ("sensitive_fields", "high", "high")

    if any(p.search(text) for p in MUTATION_PATTERNS):
        return ("mutations", "medium", "high")

    if any(p.search(text) for p in SUBSCRIPTION_PATTERNS):
        return ("subscriptions", "medium", "high")

    return ("graphql_exposure", "low", "medium")


# ---------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------

def parse_graphql_cop(raw_file: Path) -> List[Finding]:
    """
    Parse graphql-cop output into normalized path findings.

    graphql-cop emits findings in the format:
        <endpoint> :: <detail>

    Each unique (endpoint, detail) pair is normalized, classified,
    deduplicated, and returned deterministically.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    for line in raw_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or "::" not in line:
            continue

        endpoint_raw, detail = [p.strip() for p in line.split("::", 1)]

        if not endpoint_raw or not detail:
            continue

        parsed = urlparse(endpoint_raw)
        if not parsed.scheme or not parsed.netloc:
            continue

        # Normalize endpoint (strip fragment)
        normalized = parsed._replace(fragment="").geturl()

        exposure_type, severity, confidence = _classify_graphql_exposure(detail)

        key = (normalized, detail)

        if exposure_type == "unauthenticated":
            title = f"GraphQL endpoint accessible without authentication: {parsed.path}"
        elif exposure_type == "introspection":
            title = f"GraphQL introspection enabled: {parsed.path}"
        elif exposure_type == "sensitive_fields":
            title = f"GraphQL sensitive fields exposed: {parsed.path}"
        elif exposure_type == "mutations":
            title = f"GraphQL mutations allowed: {parsed.path}"
        elif exposure_type == "subscriptions":
            title = f"GraphQL subscriptions enabled: {parsed.path}"
        else:
            title = f"GraphQL exposure detected: {parsed.path}"

        if key not in findings:
            findings[key] = Finding(
                asset=normalized,
                title=title,
                tool="graphql-cop",
                kind="path",
                severity=severity,
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata={
                    "source": "graphql-cop",
                    "exposure_type": exposure_type,
                    "detail": detail,
                    "confidence": confidence,
                    "domain": parsed.netloc,
                    "path": parsed.path,
                    "technologies": ["graphql"],
                    "cwe": _get_cwe_for_exposure(exposure_type),
                },
            )
        else:
            findings[key].occurrences += 1

    # Deterministic ordering (resume-safe)
    return sorted(findings.values(), key=lambda f: (f.asset, f.title))