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
from urllib.parse import urlsplit
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
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".webm", ".pdf",
    ".zip", ".gz", ".tgz", ".tar", ".rar", ".7z",
    ".exe", ".msi", ".dmg", ".pkg", ".apk", ".ipa", ".jar",
)

# High-entropy single-segment paths (e.g., hashed bundle references). Named
# routes such as ``GetClockChallenge`` must not be rejected merely for
# being long, so this intentionally targets hash/token shapes rather than all
# long alphanumeric strings.
HEX_HASH_LIKE = re.compile(r"^[a-fA-F0-9]{24,}$")
TOKEN_LIKE = re.compile(r"^[a-zA-Z0-9_-]{32,}$")

# LinkFinder resolves every string that resembles a relative path against the
# JavaScript file URL. Strings from MIME registries and localization bundles
# can consequently become plausible-looking URLs below static directories,
# for example ``/auth/assets/application/json`` or
# ``/auth/assets/zh/SpelloutRules/spellout-cardinal``. These are resources or
# parser artifacts, not application routes that should receive active probes.
STATIC_TREE_SEGMENTS = {
    "assets", "static", "icons", "fonts", "images", "img",
    "css", "js", "scripts", "binaries",
}
API_TREE_SEGMENTS = {"api", "rest", "graphql", "gql"}
VERSIONED_API_SEGMENT = re.compile(r"^v\d+$", re.IGNORECASE)


def _is_static_tree(segments: list[str]) -> bool:
    """Identify static-resource trees without hiding explicit API namespaces."""

    lowered = [segment.lower() for segment in segments]
    if any(
        segment in API_TREE_SEGMENTS or VERSIONED_API_SEGMENT.fullmatch(segment)
        for segment in lowered
    ):
        return False
    return any(segment in STATIC_TREE_SEGMENTS for segment in lowered)


def _is_high_entropy_segment(segment: str) -> bool:
    """Conservatively recognize opaque hashes while retaining named routes."""

    if HEX_HASH_LIKE.fullmatch(segment):
        return True
    if not TOKEN_LIKE.fullmatch(segment):
        return False
    return (
        any(character.islower() for character in segment)
        and any(character.isupper() for character in segment)
        and any(character.isdigit() for character in segment)
    )


# -----------------------------------------------------------------------------
# Validation Helpers
# -----------------------------------------------------------------------------

def _is_valid_endpoint(path: str) -> bool:
    """
    Determine whether an extracted endpoint should be promoted
    to a Deadbolt path artifact.

    Validation rules:
    - Must be a string
    - Must be an absolute HTTP(S) URL or begin with "/"
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

    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return False
        base = parsed.path or "/"
    elif candidate.startswith("/"):
        base = candidate.split("?", 1)[0]
    else:
        return False

    # Reject static assets
    if base.lower().endswith(STATIC_EXTENSIONS):
        return False

    # Reject high-entropy single-segment paths
    segments = [s for s in base.split("/") if s]
    if len(segments) == 1 and _is_high_entropy_segment(segments[0]):
        return False

    # Reject MIME/locale registries and other strings resolved beneath static
    # resource trees. Explicit API namespaces remain eligible even when their
    # route happens to contain a segment such as ``assets``.
    if _is_static_tree(segments):
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

    structured = []
    for entry in endpoints:
        if isinstance(entry, str):
            structured.append({
                "resolved_url": entry,
                "raw_expression": entry,
                "source_url": None,
                "source_location": None,
                "extractor": "linkfinder-legacy",
                "evidence_status": "discovered",
                "confidence": "low",
            })
        elif isinstance(entry, dict) and entry.get("resolved_url"):
            structured.append(entry)

    for entry in sorted(
        structured,
        key=lambda item: (
            str(item.get("resolved_url", "")),
            str(item.get("source_url", "")),
            str(item.get("raw_expression", "")),
        ),
    ):
        endpoint = str(entry["resolved_url"])

        if not _is_valid_endpoint(endpoint):
            continue

        if endpoint not in findings:
            provenance = {
                "source_url": entry.get("source_url"),
                "source_location": entry.get("source_location"),
                "raw_expression": entry.get("raw_expression"),
                "extractor": entry.get("extractor", "linkfinder"),
                "evidence_status": entry.get("evidence_status", "discovered"),
                "confidence": entry.get("confidence", "low"),
                "method": entry.get("method"),
                "request_body_fields": entry.get("request_body_fields", []),
                "request_body_schema": entry.get("request_body_schema", []),
                "response_fields": entry.get("response_fields", []),
                "client_validation_rules": entry.get("client_validation_rules", []),
                "request_header_names": entry.get("request_header_names", []),
                "credentials_mode": entry.get("credentials_mode"),
                "wrapper_chain": entry.get("wrapper_chain", []),
            }
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
                    "raw_expression": entry.get("raw_expression"),
                    "source_url": entry.get("source_url"),
                    "source_location": entry.get("source_location"),
                    "extractor": entry.get("extractor", "linkfinder"),
                    "evidence_status": entry.get("evidence_status", "discovered"),
                    "confidence": entry.get("confidence", "low"),
                    "method": entry.get("method"),
                    "methods": [entry["method"]] if entry.get("method") else [],
                    "request_body_fields": entry.get("request_body_fields", []),
                    "request_body_schema": entry.get("request_body_schema", []),
                    "response_fields": entry.get("response_fields", []),
                    "client_validation_rules": entry.get("client_validation_rules", []),
                    "request_body_fields_by_method": {
                        str(entry["method"]).upper(): entry.get("request_body_fields", [])
                    } if entry.get("method") else {},
                    "request_header_names": entry.get("request_header_names", []),
                    "credentials_mode": entry.get("credentials_mode"),
                    "wrapper_chain": entry.get("wrapper_chain", []),
                    "provenance": [provenance],
                },
            )
        else:
            findings[endpoint].occurrences += 1
            provenance = findings[endpoint].metadata.setdefault("provenance", [])
            candidate = {
                "source_url": entry.get("source_url"),
                "source_location": entry.get("source_location"),
                "raw_expression": entry.get("raw_expression"),
                "extractor": entry.get("extractor", "linkfinder"),
                "evidence_status": entry.get("evidence_status", "discovered"),
                "confidence": entry.get("confidence", "low"),
                "method": entry.get("method"),
                "request_body_fields": entry.get("request_body_fields", []),
                "request_body_schema": entry.get("request_body_schema", []),
                "response_fields": entry.get("response_fields", []),
                "client_validation_rules": entry.get("client_validation_rules", []),
                "request_header_names": entry.get("request_header_names", []),
                "credentials_mode": entry.get("credentials_mode"),
                "wrapper_chain": entry.get("wrapper_chain", []),
            }
            if candidate not in provenance:
                provenance.append(candidate)
            if entry.get("evidence_status") == "inferred":
                findings[endpoint].metadata["evidence_status"] = "inferred"
                findings[endpoint].metadata["confidence"] = "medium"
                findings[endpoint].metadata["raw_expression"] = entry.get("raw_expression")
                findings[endpoint].metadata["source_url"] = entry.get("source_url")
                findings[endpoint].metadata["source_location"] = entry.get("source_location")
                findings[endpoint].metadata["extractor"] = entry.get("extractor")
                findings[endpoint].metadata["method"] = entry.get("method")
                method = entry.get("method")
                if method:
                    methods = findings[endpoint].metadata.setdefault("methods", [])
                    if method not in methods:
                        methods.append(method)
                    findings[endpoint].metadata.setdefault(
                        "request_body_fields_by_method", {}
                    )[str(method).upper()] = entry.get("request_body_fields", [])
                findings[endpoint].metadata["request_body_fields"] = entry.get(
                    "request_body_fields", []
                )
                findings[endpoint].metadata["request_body_schema"] = entry.get(
                    "request_body_schema", []
                )
                findings[endpoint].metadata["request_header_names"] = entry.get(
                    "request_header_names", []
                )
                findings[endpoint].metadata["response_fields"] = entry.get(
                    "response_fields", []
                )
                findings[endpoint].metadata["client_validation_rules"] = entry.get(
                    "client_validation_rules", []
                )
                findings[endpoint].metadata["credentials_mode"] = entry.get(
                    "credentials_mode"
                )
                findings[endpoint].metadata["wrapper_chain"] = entry.get(
                    "wrapper_chain", []
                )

    # A raw string extractor can only resolve relative strings against the
    # JavaScript bundle origin.  Static reconstruction has more context and
    # may resolve the same suffix through a base-path or cross-origin
    # variable.  Keep the raw hit as provenance on that reconstructed
    # operation instead of emitting a second, misleading endpoint.
    inferred = [
        finding for finding in findings.values()
        if finding.metadata.get("evidence_status") == "inferred"
    ]
    aliases: set[str] = set()
    for discovered in findings.values():
        if discovered.metadata.get("evidence_status") != "discovered":
            continue
        discovered_url = urlsplit(discovered.asset)
        discovered_sources = {
            item.get("source_url")
            for item in discovered.metadata.get("provenance", [])
            if isinstance(item, dict) and item.get("source_url")
        }
        matches = []
        for candidate in inferred:
            candidate_url = urlsplit(candidate.asset)
            candidate_sources = {
                item.get("source_url")
                for item in candidate.metadata.get("provenance", [])
                if isinstance(item, dict) and item.get("source_url")
            }
            same_source = bool(discovered_sources & candidate_sources)
            path_alias = (
                candidate_url.path == discovered_url.path
                or candidate_url.path.endswith(discovered_url.path)
            )
            if same_source and path_alias and candidate_url.query == discovered_url.query:
                matches.append(candidate)
        if len(matches) != 1:
            continue
        canonical = matches[0]
        canonical_provenance = canonical.metadata.setdefault("provenance", [])
        for item in discovered.metadata.get("provenance", []):
            if item not in canonical_provenance:
                canonical_provenance.append(item)
        canonical.occurrences += discovered.occurrences
        aliases.add(discovered.asset)

    # Deterministic ordering for resume stability
    return sorted(
        (finding for endpoint, finding in findings.items() if endpoint not in aliases),
        key=lambda finding: finding.asset,
    )
