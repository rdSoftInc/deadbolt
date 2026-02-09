# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief MobSF JSON report parser.
#
# This module parses MobSF JSON reports and normalizes Android security
# findings into Deadbolt Finding objects. It covers manifest analysis,
# code analysis, network security, and certificate issues.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from typing import List
import json

from main.schema.normalize import Finding


# Map MobSF severity labels to Deadbolt canonical severities
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "warning": "medium",
    "info": "info",
    "informational": "info",
    "good": "info",
}


def _normalize_severity(raw) -> str:
    """
    Normalize MobSF severity values into Deadbolt severity levels.
    """
    if raw is None:
        return "info"
    return SEVERITY_MAP.get(str(raw).lower(), "info")


def parse_mobsf(raw_file: Path) -> List[Finding]:
    """
    Parse a MobSF JSON report into normalized findings.

    The parser extracts findings from:
      1. Manifest analysis
      2. Code analysis (primary source of findings)
      3. Network security configuration
      4. Certificate analysis
    """
    findings: List[Finding] = []
    timestamp = datetime.now(timezone.utc)

    data = json.loads(raw_file.read_text(encoding="utf-8"))

    # Derive application identity
    asset = (
        data.get("package_name")
        or data.get("app_name")
        or data.get("file_name")
        or "android-app"
    )

    # --------------------------------------------------
    # 1. Manifest analysis
    # --------------------------------------------------
    manifest = data.get("manifest_analysis", {})
    if isinstance(manifest, dict):
        for item in manifest.get("manifest_findings", []):
            findings.append(
                Finding(
                    asset=asset,
                    title=item.get("title", "Manifest Issue"),
                    tool="mobsf",
                    kind="finding",
                    severity=_normalize_severity(item.get("severity")),
                    template_id=item.get("rule"),
                    occurrences=1,
                    timestamp=timestamp,
                    evidence_path=str(raw_file),
                    metadata={
                        "description": item.get("description"),
                        "component": item.get("component"),
                    },
                )
            )

    # --------------------------------------------------
    # 2. Code analysis (primary signal source)
    # --------------------------------------------------
    code_analysis = data.get("code_analysis", {})
    if isinstance(code_analysis, dict):
        findings_map = code_analysis.get("findings", {})
        if isinstance(findings_map, dict):
            for rule_id, block in findings_map.items():
                meta = block.get("metadata", {})
                files = block.get("files", {})

                findings.append(
                    Finding(
                        asset=asset,
                        title=meta.get("description", rule_id),
                        tool="mobsf",
                        kind="finding",
                        severity=_normalize_severity(meta.get("severity")),
                        template_id=rule_id,
                        occurrences=len(files),
                        timestamp=timestamp,
                        evidence_path=str(raw_file),
                        metadata={
                            "cwe": meta.get("cwe"),
                            "owasp": meta.get("owasp-mobile"),
                            "masvs": meta.get("masvs"),
                            "cvss": meta.get("cvss"),
                            "references": meta.get("ref"),
                            "files": files,
                        },
                    )
                )

    # --------------------------------------------------
    # 3. Network security configuration
    # --------------------------------------------------
    network = data.get("network_security", {})
    if isinstance(network, dict):
        for item in network.get("network_findings", []):
            findings.append(
                Finding(
                    asset=asset,
                    title="Network Security Issue",
                    tool="mobsf",
                    kind="finding",
                    severity=_normalize_severity(item.get("severity")),
                    occurrences=1,
                    timestamp=timestamp,
                    evidence_path=str(raw_file),
                    metadata={
                        "description": item.get("description"),
                        "scope": item.get("scope"),
                    },
                )
            )

    # --------------------------------------------------
    # 4. Certificate analysis
    # --------------------------------------------------
    certs = data.get("certificate_analysis", {})
    if isinstance(certs, dict):
        for sev, desc, title in certs.get("certificate_findings", []):
            findings.append(
                Finding(
                    asset=asset,
                    title=title,
                    tool="mobsf",
                    kind="finding",
                    severity=_normalize_severity(sev),
                    occurrences=1,
                    timestamp=timestamp,
                    evidence_path=str(raw_file),
                    metadata={"description": desc},
                )
            )

    return findings