# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief apktool output parser for Android manifest configuration analysis.
#
# This module parses AndroidManifest.xml extracted via apktool and normalizes
# Android configuration posture and attack surface indicators into Deadbolt
# Finding objects.
#
# The parser focuses on:
# - Manifest configuration weaknesses
# - Cleartext traffic exposure
# - Dangerous permission exposure
# - Exported component attack surface
# - SDK hardening posture
#
# Detects:
# - Debuggable application configuration
# - Backup-enabled applications
# - Cleartext traffic permission
# - Dangerous Android permission exposure
# - Exported components (activities, services, receivers, providers)
# - Legacy or outdated SDK targeting posture
# - Sensitive intent exposure in exported components
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
CURRENT_RECOMMENDED_TARGET = 34


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
    "android.intent.action.GET_CONTENT",
    "android.intent.action.OPEN_DOCUMENT",
}


# -----------------------------------------------------------------------------
# Manifest Helpers
# -----------------------------------------------------------------------------

def _bool_attr(elem: ET.Element, name: str) -> bool:
    """
    Normalize boolean Android manifest attributes.

    Returns True only if attribute explicitly equals "true".
    """

    value = elem.attrib.get(ANDROID_NS + name)
    return value is not None and value.lower() == "true"


def _parse_manifest(manifest_path: Path) -> Dict:
    """
    Parse AndroidManifest.xml extracted by apktool.

    Returns structured manifest posture data.
    """

    data = {
        "debuggable": False,
        "allow_backup": False,
        "uses_cleartext_traffic": False,
        "min_sdk": None,
        "target_sdk": None,
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
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError:
        return data

    # ------------------------------------------------------------------
    # SDK Versions
    # ------------------------------------------------------------------
    sdk = root.find("uses-sdk")
    if sdk is not None:
        min_sdk = sdk.attrib.get(f"{ANDROID_NS}minSdkVersion")
        target_sdk = sdk.attrib.get(f"{ANDROID_NS}targetSdkVersion")

        if min_sdk:
            data["min_sdk"] = int(min_sdk)
        if target_sdk:
            data["target_sdk"] = int(target_sdk)

    # ------------------------------------------------------------------
    # Permissions
    # ------------------------------------------------------------------
    for perm in root.findall("uses-permission"):
        name = perm.attrib.get(f"{ANDROID_NS}name", "")
        if name in DANGEROUS_PERMISSIONS:
            data["dangerous_permissions"].append(name)

    # ------------------------------------------------------------------
    # Application-Level Config
    # ------------------------------------------------------------------
    app = root.find("application")
    if app is None:
        return data

    data["debuggable"] = _bool_attr(app, "debuggable")
    data["allow_backup"] = _bool_attr(app, "allowBackup")
    data["uses_cleartext_traffic"] = _bool_attr(app, "usesCleartextTraffic")

    # ------------------------------------------------------------------
    # Exported Components + Intent Filters
    # ------------------------------------------------------------------
    for tag in ["activity", "service", "receiver", "provider"]:
        for comp in app.findall(tag):
            if comp.attrib.get(f"{ANDROID_NS}exported") == "true":
                name = comp.attrib.get(f"{ANDROID_NS}name", "")
                if name:
                    data["exported"][tag].append(name)

                for intent_filter in comp.findall("intent-filter"):
                    for action in intent_filter.findall("action"):
                        action_name = action.attrib.get(
                            f"{ANDROID_NS}name", ""
                        )
                        if action_name:
                            data["intent_filters"].append(action_name)

    return data


# -----------------------------------------------------------------------------
# Main Parser
# -----------------------------------------------------------------------------

def parse_apktool(raw_file: Path) -> List[Finding]:
    """
    Parse apktool execution output into normalized Deadbolt findings.

    Generates:
        - kind="finding" for configuration weaknesses
        - kind="asset" for exported attack surface
    """

    findings: Dict[Tuple[str, str], Finding] = {}
    timestamp = datetime.now(timezone.utc)

    data = json.loads(raw_file.read_text(encoding="utf-8"))
    manifest_relative = data.get("manifest", "AndroidManifest.xml")
    manifest_path = raw_file.parent / manifest_relative

    if not manifest_path.exists():
        raise RuntimeError(
            f"apktool parser error: AndroidManifest.xml not found at {manifest_path}"
        )

    manifest = _parse_manifest(manifest_path)

    # ------------------------------------------------------------------
    # Internal Dedup Helper
    # ------------------------------------------------------------------
    def add_finding(asset: str, title: str, kind: str,
                    severity: str | None = None,
                    metadata: Dict | None = None):

        key = (asset, title)

        if key not in findings:
            findings[key] = Finding(
                asset=asset,
                title=title,
                tool="apktool",
                kind=kind,
                severity=severity,
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(manifest_path),
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
    # 3. Cleartext Traffic
    # ------------------------------------------------------------------
    if manifest["uses_cleartext_traffic"]:
        add_finding(
            "AndroidManifest.xml",
            "Cleartext traffic permitted",
            "finding",
            "high",
            {"category": "network_security"},
        )

    # ------------------------------------------------------------------
    # 4. Dangerous Permissions
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
    # 5. Exported Components (Attack Surface)
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
    # 6. SDK Posture
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
            {"category": "sdk_posture"},
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