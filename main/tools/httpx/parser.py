# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief httpx output parser for HTTP service enrichment and validation.
#
# This module parses newline-delimited JSON output from httpx and enriches
# discovered services with HTTP metadata, security indicators, and response
# analysis. Findings produced here are primarily *attack surface* (assets/paths)
# used by downstream enumeration and vulnerability tooling.
#
# Design notes:
# - httpx is used in two roles:
#   1) discovery/httpx: validates assets (hosts/base URLs) -> produces "assets"
#   2) enumeration/httpx_paths: validates/enriches URLs/paths -> produces "paths"
# - The runtime registry may post-process findings (e.g., reclassify kind="path").
# - Output ordering is deterministic to support resumable state hashing.
#
# Detects / Enriches:
# - Live HTTP services with status code analysis
# - CDN and WAF protection layers (cdn_name/cdn_type)
# - Technology stack identification (tech)
# - Redirect targets (location)
# - Authentication/authorization boundaries (401/403)
# - Page type hints (knowledgebase / title)
#
# Author: Rolstan Robert D'souza
# Date: 2026
#
# -----------------------------------------------------------------------------

from pathlib import Path
import json
from datetime import datetime, timezone
from typing import List, Tuple, Dict
from urllib.parse import urlparse
import re

from main.schema.normalize import Finding


# ---------------------------------------------------------------------
# Heuristic Pattern Sets
# ---------------------------------------------------------------------

# Technologies that typically imply higher attack surface or frequent CVE density.
# Note: this is NOT a vulnerability verdict; it is used for prioritization.
_DANGEROUS_TECH_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in {
        r"wordpress", r"joomla", r"drupal", r"magento",
        r"jenkins", r"gitlab", r"grafana",
        r"mongodb", r"elasticsearch", r"redis",
        r"struts", r"spring",
        r"debug", r"test",
    }
]

# Suspicious redirect targets and environmental leakage hints.
# Kept intentionally broad; used only for metadata tagging.
_SUSPICIOUS_TARGET_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in {
        r"\bdefault\b", r"\badmin\b", r"\broot\b", r"\btest\b",
        r"example\.com", r"localhost", r"127\.0\.0\.1",
    }
]


# ---------------------------------------------------------------------
# Classification Helpers
# ---------------------------------------------------------------------

def _classify_status_code(status: int, cdn: bool = False) -> Tuple[str, str]:
    """
    Classify HTTP status code significance and severity for prioritization.

    Returns:
        (significance: str, severity: str)

    Severity here represents *triage priority*, not vulnerability certainty.
    """
    if status == 200:
        # If behind CDN/WAF, treat as lower priority for pure recon,
        # but still a valid live asset.
        return ("content_found", "low" if cdn else "medium")

    if status == 204:
        return ("no_content", "low")

    if status in (301, 302, 303, 307, 308):
        # Redirects can reveal internal routing and auth boundaries.
        return ("redirect", "medium")

    if status == 401:
        # Endpoint exists and is gated; valuable for auth boundary mapping.
        return ("auth_required", "medium")

    if status == 403:
        # Endpoint exists and is forbidden; often indicates protected surface.
        return ("forbidden", "medium")

    if status == 404:
        return ("not_found", "low")

    if status == 405:
        return ("method_not_allowed", "low")

    if status in (500, 502, 503, 504):
        # Server errors may leak stack traces or misconfig; still recon signal.
        return ("server_error", "low")

    return ("other", "low")


def _classify_protection(cdn_name: str | None, cdn_type: str | None) -> Tuple[str, str]:
    """
    Classify protection and hosting level from httpx CDN detection fields.

    Returns:
        (protection_level: str, hosting_type: str)
    """
    if not cdn_name:
        return ("unprotected", "direct_hosting")

    name = cdn_name.lower()
    ctype = (cdn_type or "").lower()

    if ctype == "waf":
        if "cloudflare" in name:
            return ("cloudflare_waf", "cdn_protected")
        if "aws" in name:
            return ("aws_waf", "cdn_protected")
        return ("waf_protected", "cdn_protected")

    if ctype == "cloud":
        if "aws" in name:
            return ("aws_hosted", "cloud")
        if "azure" in name:
            return ("azure_hosted", "cloud")
        if "gcp" in name or "google" in name:
            return ("gcp_hosted", "cloud")
        return ("cloud_hosted", "cloud")

    if ctype == "cdn":
        if "akamai" in name:
            return ("akamai_cdn", "cdn_hosted")
        if "cloudflare" in name:
            return ("cloudflare_cdn", "cdn_hosted")
        return ("cdn_hosted", "cdn_hosted")

    return ("other_protection", "unknown")


def _analyze_technologies(tech_list: list) -> Tuple[bool, List[str]]:
    """
    Identify higher-risk technologies for triage prioritization.

    Returns:
        (has_dangerous: bool, dangerous_techs: list[str])
    """
    if not isinstance(tech_list, list) or not tech_list:
        return False, []

    dangerous: List[str] = []
    for tech in tech_list:
        if not isinstance(tech, str):
            continue
        if any(p.search(tech) for p in _DANGEROUS_TECH_PATTERNS):
            dangerous.append(tech)

    # De-duplicate while preserving deterministic order
    dangerous = sorted(set(dangerous), key=lambda x: x.lower())
    return (len(dangerous) > 0), dangerous


def _extract_page_type(knowledgebase: dict | None, title: str | None) -> str:
    """
    Map httpx knowledgebase hints into security-relevant page types.

    If knowledgebase is missing, attempts a minimal title-based inference.
    """
    if isinstance(knowledgebase, dict):
        page_type = knowledgebase.get("PageType", "other")
        type_map = {
            "login": "login_page",
            "error": "error_page",
            "database": "database_interface",
            "cms": "cms",
            "admin": "admin_panel",
            "other": "other",
        }
        return type_map.get(str(page_type).lower(), str(page_type).lower())

    # Lightweight fallback based on title text
    t = (title or "").lower()
    if "login" in t or "sign in" in t or "signin" in t:
        return "login_page"
    if "error" in t or "exception" in t:
        return "error_page"
    return "unknown"


def _looks_suspicious_target(location: str | None) -> bool:
    """Heuristic: flag suspicious redirect targets (localhost/example/admin hints)."""
    if not location or not isinstance(location, str):
        return False
    return any(p.search(location) for p in _SUSPICIOUS_TARGET_PATTERNS)


def _normalize_url(url: str) -> str:
    """
    Normalize URL for stable de-duplication.

    We keep normalization conservative to avoid collapsing distinct assets.
    """
    url = url.strip()
    parsed = urlparse(url)

    # If urlparse fails to find scheme/netloc, return as-is (still useful to store).
    if not parsed.scheme or not parsed.netloc:
        return url

    # Drop fragments for stability
    return parsed._replace(fragment="").geturl()


# ---------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------

def parse_httpx(raw_file: Path) -> List[Finding]:
    """
    Parse httpx JSONL output into normalized findings.

    httpx emits one JSON object per line describing a live HTTP service.
    Each entry is analyzed for triage significance and enriched with
    CDN/WAF, technology, and response metadata.

    Important:
    - This parser returns *attack surface* findings by default (kind="asset").
      The runtime registry may reclassify them to kind="path" for enrichment mode.
    - Output is deterministic (sorted) and de-duplicated by normalized URL.
    """
    timestamp = datetime.now(timezone.utc)

    # De-duplicate by normalized URL. Preserve the "best" record if duplicates appear.
    # Best = highest triage severity, then richer metadata.
    findings_by_url: Dict[str, Finding] = {}

    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url_raw = data.get("url")
            if not isinstance(url_raw, str) or not url_raw.strip():
                continue

            url = _normalize_url(url_raw)

            # Core fields (httpx schema varies by flags/version; treat as optional)
            status = data.get("status_code")
            if not isinstance(status, int):
                status = None

            cdn_name = data.get("cdn_name")
            cdn_type = data.get("cdn_type")
            tech_list = data.get("tech", [])
            if not isinstance(tech_list, list):
                tech_list = []

            location = data.get("location")
            title = data.get("title") or "Live HTTP Service"
            content_length = data.get("content_length", 0)
            content_type = data.get("content_type", "")
            response_time = data.get("time", "")

            # Status code analysis
            status_sig, status_sev = (
                _classify_status_code(status, bool(cdn_name))
                if status is not None
                else ("unknown", "low")
            )

            # Protection classification
            protection, hosting = _classify_protection(
                cdn_name if isinstance(cdn_name, str) else None,
                cdn_type if isinstance(cdn_type, str) else None,
            )

            # Technology analysis
            has_dangerous, dangerous_techs = _analyze_technologies(tech_list)

            # Page type
            page_type = _extract_page_type(data.get("knowledgebase"), title)

            # Redirect target heuristic
            suspicious_redirect = _looks_suspicious_target(location if isinstance(location, str) else None)

            # Determine overall triage severity (conservative, recon-oriented)
            severity = status_sev
            if has_dangerous:
                severity = "high"
            elif status in (401, 403):
                severity = "medium"
            elif suspicious_redirect:
                severity = "medium"
            elif isinstance(cdn_name, str) and "cloudflare" in cdn_name.lower():
                severity = "low"

            # Human-readable title (stable and concise)
            if status in (301, 302, 303, 307, 308) and isinstance(location, str) and location:
                title_text = f"Redirect detected: {url} → {location}"
                if suspicious_redirect:
                    title_text += " [suspicious target]"
            elif status == 401:
                title_text = f"Authentication required: {url}"
            elif status == 403:
                title_text = f"Forbidden: {url}"
            elif status in (500, 502, 503, 504):
                title_text = f"Server error detected: {url}"
            elif has_dangerous and dangerous_techs:
                title_text = f"Dangerous technologies detected: {url} ({', '.join(dangerous_techs)})"
            elif page_type == "login_page":
                title_text = f"Login page detected: {url}"
            else:
                title_text = title if isinstance(title, str) and title.strip() else f"Live HTTP Service: {url}"

            candidate = Finding(
                asset=url,
                title=title_text,
                tool="httpx",
                # Default: attack surface asset. httpx_paths postprocess will flip to kind="path".
                kind="asset",
                status_code=status,
                severity=severity,
                technologies=tech_list,
                webserver=data.get("webserver"),
                cdn=bool(cdn_name),
                cdn_name=cdn_name if isinstance(cdn_name, str) else None,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata={
                    "source": "httpx",
                    "status_significance": status_sig,
                    "protection_level": protection,
                    "hosting_type": hosting,
                    "page_type": page_type,
                    "content_type": content_type,
                    "content_length": content_length,
                    "response_time": response_time,
                    "has_dangerous_tech": has_dangerous,
                    "dangerous_techs": dangerous_techs,
                    "dns_ips": data.get("a", []) if isinstance(data.get("a", []), list) else [],
                    "cname": data.get("cname", []) if isinstance(data.get("cname", []), list) else [],
                    "location": location,
                    "suspicious_redirect_target": suspicious_redirect,
                    "host_ip": data.get("host_ip"),
                    "location_geo": data.get("location"),
                },
            )

            # De-duplication: keep the "best" record
            existing = findings_by_url.get(url)
            if not existing:
                findings_by_url[url] = candidate
                continue

            # Prefer higher severity; if equal, prefer richer metadata / a status_code
            if severity_rank.get(candidate.severity or "low", 1) > severity_rank.get(existing.severity or "low", 1):
                candidate.occurrences = (existing.occurrences or 1) + 1
                findings_by_url[url] = candidate
            else:
                existing.occurrences = (existing.occurrences or 1) + 1
                # Merge a few useful metadata fields if missing
                if existing.status_code is None and candidate.status_code is not None:
                    existing.status_code = candidate.status_code
                if not existing.technologies and candidate.technologies:
                    existing.technologies = candidate.technologies
                if not existing.cdn_name and candidate.cdn_name:
                    existing.cdn_name = candidate.cdn_name

    # Deterministic ordering (resume-safe)
    return sorted(findings_by_url.values(), key=lambda f: (f.asset, f.title))