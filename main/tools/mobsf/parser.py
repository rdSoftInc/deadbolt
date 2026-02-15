# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief MobSF JSON report parser (Android & iOS) for Deadbolt normalization.
#
# This module parses MobSF JSON analysis reports (Android APK/AAB and iOS IPA)
# and converts security findings into normalized Deadbolt Finding objects.
#
# The parser enforces:
# - Deterministic ordering
# - Controlled severity normalization
# - Duplicate suppression
# - Platform-aware parsing logic
#
# ANDROID COVERAGE:
# - Manifest analysis findings
# - Code analysis findings
# - Network security findings
# - Hardcoded secrets summary
# - Privacy tracker detection
#
# iOS COVERAGE:
# - App Transport Security (ATS) findings
# - Binary analysis findings
# - Mach-O hardening checks
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple, Dict

from main.schema.normalize import Finding


# -----------------------------------------------------------------------------
# Severity Normalization
# -----------------------------------------------------------------------------

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

    Unknown or missing severities default to "info".
    """
    if raw is None:
        return "info"

    return SEVERITY_MAP.get(str(raw).lower(), "info")


# -----------------------------------------------------------------------------
# Platform Detection
# -----------------------------------------------------------------------------

def _detect_platform(data: dict) -> str:
    """
    Detect whether the MobSF report corresponds to Android or iOS.
    """

    if any(k in data for k in ("ats_analysis", "macho_analysis", "dylib_analysis")):
        return "ios"

    if any(k in data for k in ("manifest_analysis", "certificate_analysis", "apkid")):
        return "android"

    if "bundle_id" in data:
        return "ios"

    return "android"


# -----------------------------------------------------------------------------
# Deduplication
# -----------------------------------------------------------------------------

def _dedupe(findings: List[Finding]) -> List[Finding]:
    """
    Remove duplicate findings using (asset, title, tool) identity key.
    """

    seen: set[Tuple[str, str, str]] = set()
    result: List[Finding] = []

    for f in findings:
        key = (f.asset, f.title, f.tool)
        if key not in seen:
            seen.add(key)
            result.append(f)

    return result


# -----------------------------------------------------------------------------
# Android Parsing
# -----------------------------------------------------------------------------

def _parse_android(data: dict, asset: str, ts: datetime, raw: Path) -> List[Finding]:
    """
    Parse Android-specific MobSF report sections.
    """

    findings: List[Finding] = []

    # -----------------------------------------------------------------
    # 1. Manifest Analysis
    # -----------------------------------------------------------------

    manifest = data.get("manifest_analysis", {})

    for item in sorted(
        manifest.get("manifest_findings", []),
        key=lambda x: x.get("title", "")
    ):
        findings.append(
            Finding(
                asset=asset,
                title=item.get("title", "Manifest Issue"),
                tool="mobsf",
                kind="finding",
                severity=_normalize_severity(item.get("severity")),
                template_id=item.get("rule"),
                occurrences=1,
                timestamp=ts,
                evidence_path=str(raw),
                metadata={
                    "category": "manifest",
                    "description": item.get("description"),
                },
            )
        )

    # -----------------------------------------------------------------
    # 2. Code Analysis
    # -----------------------------------------------------------------

    code = data.get("code_analysis", {}).get("findings", {})

    for rule_id in sorted(code.keys()):
        block = code[rule_id]
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
                timestamp=ts,
                evidence_path=str(raw),
                metadata={
                    "category": "code",
                    "cwe": meta.get("cwe"),
                    "masvs": meta.get("masvs"),
                },
            )
        )

    # -----------------------------------------------------------------
    # 3. Network Security
    # -----------------------------------------------------------------

    network = data.get("network_security", {}).get("network_findings", [])

    for item in sorted(network, key=lambda x: x.get("title", "")):
        findings.append(
            Finding(
                asset=asset,
                title=item.get("title", "Network Issue"),
                tool="mobsf",
                kind="finding",
                severity=_normalize_severity(item.get("severity")),
                occurrences=1,
                timestamp=ts,
                evidence_path=str(raw),
                metadata={"category": "network"},
            )
        )

    # -----------------------------------------------------------------
    # 4. Hardcoded Secrets Summary
    # -----------------------------------------------------------------

    secrets = data.get("secrets", [])

    if isinstance(secrets, list) and secrets:
        findings.append(
            Finding(
                asset=asset,
                title=f"Hardcoded secrets detected ({len(secrets)} found)",
                tool="mobsf",
                kind="finding",
                severity="critical",
                occurrences=len(secrets),
                timestamp=ts,
                evidence_path=str(raw),
                metadata={"category": "secrets"},
            )
        )

    # -----------------------------------------------------------------
    # 5. Privacy Trackers
    # -----------------------------------------------------------------

    trackers = data.get("trackers", {}).get("trackers", [])

    for tracker in sorted(trackers, key=lambda x: x.get("name", "")):
        findings.append(
            Finding(
                asset=asset,
                title=f"Privacy Tracker: {tracker.get('name', 'Unknown')}",
                tool="mobsf",
                kind="finding",
                severity="medium",
                occurrences=1,
                timestamp=ts,
                evidence_path=str(raw),
                metadata={"category": "tracker"},
            )
        )

    return findings


# -----------------------------------------------------------------------------
# iOS Parsing
# -----------------------------------------------------------------------------

def _parse_ios(data: dict, asset: str, ts: datetime, raw: Path) -> List[Finding]:
    """
    Parse iOS-specific MobSF report sections.
    """

    findings: List[Finding] = []

    # -----------------------------------------------------------------
    # 1. App Transport Security (ATS)
    # -----------------------------------------------------------------

    ats = data.get("ats_analysis", {}).get("ats_findings", [])

    for item in sorted(ats, key=lambda x: x.get("issue", "")):
        findings.append(
            Finding(
                asset=asset,
                title=item.get("issue", "ATS Issue"),
                tool="mobsf",
                kind="finding",
                severity=_normalize_severity(item.get("severity")),
                occurrences=1,
                timestamp=ts,
                evidence_path=str(raw),
                metadata={"category": "ats"},
            )
        )

    # -----------------------------------------------------------------
    # 2. Binary Analysis
    # -----------------------------------------------------------------

    binary = data.get("binary_analysis", {}).get("findings", {})

    for rule_id in sorted(binary.keys()):
        block = binary[rule_id]

        findings.append(
            Finding(
                asset=asset,
                title=rule_id,
                tool="mobsf",
                kind="finding",
                severity=_normalize_severity(block.get("severity")),
                template_id=rule_id,
                occurrences=1,
                timestamp=ts,
                evidence_path=str(raw),
                metadata={"category": "binary"},
            )
        )

    # -----------------------------------------------------------------
    # 3. Mach-O Hardening Checks
    # -----------------------------------------------------------------

    macho = data.get("macho_analysis", {})

    for check, value in sorted(macho.items()):
        if isinstance(value, dict) and "severity" in value:

            sev = _normalize_severity(value.get("severity"))

            if sev != "info":
                findings.append(
                    Finding(
                        asset=asset,
                        title=value.get("description", f"Mach-O: {check}"),
                        tool="mobsf",
                        kind="finding",
                        severity=sev,
                        occurrences=1,
                        timestamp=ts,
                        evidence_path=str(raw),
                        metadata={"category": "macho"},
                    )
                )

    return findings


# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------

def parse_mobsf(raw_file: Path) -> List[Finding]:
    """
    Parse a MobSF JSON report (Android or iOS) and return normalized findings.

    The parser:
    - Detects platform automatically
    - Applies platform-specific parsing
    - Deduplicates output
    - Preserves deterministic ordering
    """

    ts = datetime.now(timezone.utc)
    data = json.loads(raw_file.read_text(encoding="utf-8"))

    asset = (
        data.get("package_name")
        or data.get("bundle_id")
        or data.get("app_name")
        or "mobile-app"
    )

    platform = _detect_platform(data)

    if platform == "ios":
        findings = _parse_ios(data, asset, ts, raw_file)
    else:
        findings = _parse_android(data, asset, ts, raw_file)

    findings = _dedupe(findings)

    # Deterministic ordering for pipeline stability
    return sorted(findings, key=lambda f: (f.asset, f.severity or "", f.title))