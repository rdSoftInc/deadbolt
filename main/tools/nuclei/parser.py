# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief nuclei output parser for vulnerability detection and classification.
#
# This module parses nuclei JSONL output and normalizes vulnerability findings
# into Deadbolt Finding objects. Findings are de-duplicated by
# (asset, template_id) and enriched with CWE/CVE, CVSS, and OWASP mappings.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any

from main.schema.normalize import Finding


# ---------------------------------------------------------------------
# Vulnerability Keyword Classification
# ---------------------------------------------------------------------

VULN_TYPE_KEYWORDS = {
    "xss": ("cross_site_scripting", "high"),
    "sqli": ("sql_injection", "high"),
    "nosqli": ("nosql_injection", "high"),
    "ssrf": ("server_side_request_forgery", "high"),
    "ssti": ("server_side_template_injection", "high"),
    "open-redirect": ("open_redirect", "medium"),
    "cors": ("cors_misconfiguration", "medium"),
    "auth": ("authentication_bypass", "high"),
    "rce": ("remote_code_execution", "critical"),
    "cve": ("known_vulnerability", "high"),
}


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------
# Classification Helpers
# ---------------------------------------------------------------------

def _normalize_severity(sev: str | None) -> str:
    """Normalize severity string to Deadbolt standard."""
    if not isinstance(sev, str):
        return "info"
    sev = sev.lower().strip()
    return sev if sev in SEVERITY_ORDER else "info"


def _classify_vulnerability(template_id: str, tags: List[str], name: str) -> Tuple[str, str]:
    """
    Classify vulnerability type using template_id, tags, and name.
    Returns:
        (vulnerability_type, matched_keyword)
    """
    search_text = f"{template_id} {' '.join(tags)} {name}".lower()

    for keyword, (vuln_type, _) in VULN_TYPE_KEYWORDS.items():
        if keyword in search_text:
            return vuln_type, keyword

    return "other_vulnerability", "other"


def _extract_cvss_severity(cvss_score: float) -> str:
    """Map CVSS score to severity."""
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    if cvss_score > 0:
        return "low"
    return "info"


def _map_cwe_to_owasp(cwe_ids: List[str]) -> List[str]:
    """Map CWE IDs to OWASP Top 10 2021 categories."""
    cwe_to_owasp = {
        "cwe-79": "A03:2021 Injection",
        "cwe-89": "A03:2021 Injection",
        "cwe-94": "A03:2021 Injection",
        "cwe-601": "A05:2021 Security Misconfiguration",
        "cwe-917": "A06:2021 Vulnerable Components",
    }

    owasp = []
    for cwe in cwe_ids:
        key = str(cwe).lower()
        mapped = cwe_to_owasp.get(key)
        if mapped and mapped not in owasp:
            owasp.append(mapped)

    return owasp


def _safe_list(value: Any) -> List[str]:
    """Ensure value is a list of strings."""
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


# ---------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------

def parse_nuclei(raw_file: Path) -> List[Finding]:
    """
    Parse nuclei JSONL output into normalized vulnerability findings.

    De-duplicates findings by (asset, template_id).
    Keeps highest observed severity per finding.
    Aggregates occurrence count.
    """

    findings: Dict[Tuple[str, str], Finding] = {}
    timestamp = datetime.now(timezone.utc)

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            asset = data.get("host") or data.get("matched") or data.get("url")
            template_id = data.get("template-id")

            if not asset or not template_id:
                continue

            info = data.get("info", {})
            title = info.get("name", "Nuclei Finding")

            template_severity = _normalize_severity(info.get("severity"))

            tags = _safe_list(info.get("tags"))
            description = info.get("description", "")

            references = _safe_list(info.get("reference"))

            classification = info.get("classification", {})

            cwe_ids = _safe_list(classification.get("cwe-id"))
            cve_id = classification.get("cve-id")

            # CVSS parsing
            cvss_score = None
            cvss_vector = None

            score_str = classification.get("cvss-score")
            metrics = classification.get("cvss-metrics")

            if score_str:
                try:
                    cvss_score = float(score_str)
                except ValueError:
                    cvss_score = None

            if isinstance(metrics, str) and "CVSS:" in metrics:
                try:
                    cvss_vector = metrics.split("CVSS:")[-1].split()[0]
                except Exception:
                    pass

            # Determine severity
            if cvss_score is not None:
                final_severity = _extract_cvss_severity(cvss_score)
            else:
                final_severity = template_severity

            vuln_type, primary_keyword = _classify_vulnerability(
                template_id, tags, title
            )

            matched_at = data.get("matched-at")
            host_ip = data.get("ip")

            key = (asset, template_id)

            if key not in findings:
                finding = Finding(
                    asset=asset,
                    title=title,
                    tool="nuclei",
                    kind="finding",
                    severity=final_severity,
                    template_id=template_id,
                    timestamp=timestamp,
                    evidence_path=str(raw_file),
                    metadata={
                        "source": "nuclei",
                        "vulnerability_type": vuln_type,
                        "description": description,
                        "matched_at": matched_at,
                        "cwe_ids": cwe_ids,
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "tags": tags,
                        "references": references,
                        "template_url": data.get("template-url"),
                        "host_ip": host_ip,
                        "owasp": _map_cwe_to_owasp(cwe_ids),
                        "primary_keyword": primary_keyword,
                    },
                )
                finding.occurrences = 1
                findings[key] = finding

            else:
                existing = findings[key]
                existing.occurrences += 1

                # Keep highest severity
                if SEVERITY_ORDER.get(final_severity, 0) > SEVERITY_ORDER.get(
                    existing.severity or "info", 0
                ):
                    existing.severity = final_severity
                    existing.title = title

                # Update metadata with latest match context
                if matched_at:
                    existing.metadata["matched_at"] = matched_at
                if cvss_score:
                    existing.metadata["cvss_score"] = cvss_score
                if cvss_vector:
                    existing.metadata["cvss_vector"] = cvss_vector

    # Deterministic output ordering
    return sorted(findings.values(), key=lambda f: (f.asset, f.template_id))