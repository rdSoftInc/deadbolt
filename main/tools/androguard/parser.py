# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief Androguard output parser for Android manifest and signing analysis.
#
# This module parses structured JSON output produced by androguard and
# normalizes Android security posture findings into Deadbolt Finding objects.
#
# The parser focuses on:
# - Configuration weaknesses
# - Signing posture
# - Permission exposure
# - Exported component attack surface
# - SDK hardening posture
#
# Detects:
# - Debuggable application configuration
# - Backup-enabled applications
# - Dangerous Android permission exposure
# - Exported components (activities, services, receivers, providers)
# - Legacy or outdated SDK targeting
# - Weak or incomplete APK signing schemes
# - Sensitive intent exposure in exported activities
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Tuple
import xml.etree.ElementTree as ET

from main.schema.normalize import Finding


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
CURRENT_RECOMMENDED_TARGET = 36


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
}


SENSITIVE_INTENT_ACTIONS = {
    "android.intent.action.MAIN",
    "android.intent.action.VIEW",
    "android.intent.action.EDIT",
    "android.intent.action.SEND",
}


# -----------------------------------------------------------------------------
# Manifest Parsing
# -----------------------------------------------------------------------------

def _parse_manifest_xml(axml: str) -> Dict:
    """
    Parse AndroidManifest XML content extracted by androguard.

    Returns structured manifest security posture data.
    """

    manifest_data = {
        "min_sdk": None,
        "target_sdk": None,
        "debuggable": False,
        "allow_backup": False,
        "dangerous_permissions": [],
        "exported": {
            "activity": [],
            "service": [],
            "receiver": [],
            "provider": [],
        },
        "intent_filters": [],
    }

    try:
        root = ET.fromstring(axml)
    except ET.ParseError:
        return manifest_data

    # SDK extraction
    sdk = root.find("uses-sdk")
    if sdk is not None:
        min_sdk = sdk.attrib.get(f"{ANDROID_NS}minSdkVersion")
        target_sdk = sdk.attrib.get(f"{ANDROID_NS}targetSdkVersion")

        if min_sdk:
            manifest_data["min_sdk"] = int(min_sdk)
        if target_sdk:
            manifest_data["target_sdk"] = int(target_sdk)

    # Permissions
    for perm in root.findall("uses-permission"):
        perm_name = perm.attrib.get(f"{ANDROID_NS}name", "")
        if perm_name in DANGEROUS_PERMISSIONS:
            manifest_data["dangerous_permissions"].append(perm_name)

    # Application-level config
    app = root.find("application")
    if app is None:
        return manifest_data

    manifest_data["debuggable"] = (
        app.attrib.get(f"{ANDROID_NS}debuggable") == "true"
    )
    manifest_data["allow_backup"] = (
        app.attrib.get(f"{ANDROID_NS}allowBackup") == "true"
    )

    # Exported components
    for tag in ["activity", "service", "receiver", "provider"]:
        for comp in app.findall(tag):
            if comp.attrib.get(f"{ANDROID_NS}exported") == "true":
                name = comp.attrib.get(f"{ANDROID_NS}name", "")
                if name:
                    manifest_data["exported"][tag].append(name)

                # Collect intent actions
                for intent_filter in comp.findall("intent-filter"):
                    for action in intent_filter.findall("action"):
                        action_name = action.attrib.get(
                            f"{ANDROID_NS}name", ""
                        )
                        if action_name:
                            manifest_data["intent_filters"].append(action_name)

    return manifest_data


def _parse_signing_text(sign_text: str) -> Dict[str, bool]:
    """
    Extract signing scheme indicators from androguard signing output.
    """

    return {
        "v1": "Is signed v1: True" in sign_text,
        "v2": "Is signed v2: True" in sign_text,
        "v3": "Is signed v3: True" in sign_text,
    }


# -----------------------------------------------------------------------------
# Main Parser
# -----------------------------------------------------------------------------

def parse_androguard(raw_file: Path) -> List[Finding]:
    """
    Parse androguard JSON output into normalized Deadbolt findings.

    Generates:
        - kind="finding" for configuration and signing weaknesses
        - kind="asset" for exported attack surface
    """

    findings: Dict[Tuple[str, str], Finding] = {}
    timestamp = datetime.now(timezone.utc)

    data = json.loads(raw_file.read_text(encoding="utf-8"))

    manifest = _parse_manifest_xml(data.get("axml", ""))
    signing = _parse_signing_text(data.get("sign", ""))

    # ------------------------------------------------------------------
    # Helper to add/dedupe findings
    # ------------------------------------------------------------------
    def add_finding(asset: str, title: str, kind: str,
                    severity: str | None = None,
                    metadata: Dict | None = None):

        key = (asset, title)

        if key not in findings:
            findings[key] = Finding(
                asset=asset,
                title=title,
                tool="androguard",
                kind=kind,
                severity=severity,
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata=metadata or {},
            )
        else:
            findings[key].occurrences += 1

    # ------------------------------------------------------------------
    # 1. Debuggable
    # ------------------------------------------------------------------
    if manifest["debuggable"]:
        add_finding(
            "AndroidManifest.xml",
            "Application is debuggable",
            "finding",
            "high",
            {"category": "insecure_config"},
        )

    # ------------------------------------------------------------------
    # 2. Backup Enabled
    # ------------------------------------------------------------------
    if manifest["allow_backup"]:
        add_finding(
            "AndroidManifest.xml",
            "Application allows backup",
            "finding",
            "medium",
            {"category": "insecure_config"},
        )

    # ------------------------------------------------------------------
    # 3. Dangerous Permissions
    # ------------------------------------------------------------------
    for perm in sorted(manifest["dangerous_permissions"]):
        add_finding(
            perm,
            "Dangerous Android permission requested",
            "finding",
            "low",
            {
                "category": "permission_exposure",
                "permission": perm,
            },
        )

    # ------------------------------------------------------------------
    # 4. Exported Components (Attack Surface)
    # ------------------------------------------------------------------
    for comp_type, items in manifest["exported"].items():
        for item in sorted(items):
            add_finding(
                item,
                f"Exported {comp_type.capitalize()} detected",
                "asset",
                None,
                {
                    "category": "exported_component",
                    "component_type": comp_type,
                },
            )

    # ------------------------------------------------------------------
    # 5. SDK Posture
    # ------------------------------------------------------------------
    if manifest["min_sdk"] and manifest["min_sdk"] < 21:
        add_finding(
            "AndroidManifest.xml",
            f"Minimum SDK version is legacy (SDK {manifest['min_sdk']})",
            "finding",
            "medium",
            {"category": "sdk_posture"},
        )

    if (
        manifest["target_sdk"]
        and manifest["target_sdk"] < CURRENT_RECOMMENDED_TARGET
    ):
        add_finding(
            "AndroidManifest.xml",
            f"Target SDK version outdated (SDK {manifest['target_sdk']})",
            "finding",
            "low",
            {
                "category": "sdk_posture",
                "recommended_target_sdk": CURRENT_RECOMMENDED_TARGET,
                "policy": "Google Play phone/tablet new apps and updates from 2026-08-31",
            },
        )

    # ------------------------------------------------------------------
    # 6. Signing Posture
    # ------------------------------------------------------------------
    v1, v2, v3 = signing["v1"], signing["v2"], signing["v3"]

    if v1 and not v2 and not v3:
        add_finding(
            "APK Signing",
            "APK uses legacy v1 signing only",
            "finding",
            "high",
            {"category": "signing"},
        )
    elif not v2 and not v3:
        add_finding(
            "APK Signing",
            "APK missing modern signing schemes (v2/v3)",
            "finding",
            "medium",
            {"category": "signing"},
        )
    elif not v3:
        add_finding(
            "APK Signing",
            "APK not signed with v3 scheme",
            "finding",
            "low",
            {"category": "signing"},
        )

    # ------------------------------------------------------------------
    # 7. Sensitive Intent Exposure
    # ------------------------------------------------------------------
    sensitive = [
        i for i in manifest["intent_filters"]
        if i in SENSITIVE_INTENT_ACTIONS
    ]

    if sensitive and manifest["exported"]["activity"]:
        add_finding(
            ", ".join(sorted(set(sensitive))),
            "Exported activities use sensitive intent actions",
            "finding",
            "medium",
            {"category": "intent_exposure"},
        )

    # Deterministic ordering
    return sorted(findings.values(), key=lambda f: (f.asset, f.title))
