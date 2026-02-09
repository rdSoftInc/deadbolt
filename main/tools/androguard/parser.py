# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief Androguard output parser for Android security analysis.
#
# This module parses Androguard CLI output and generates normalized Deadbolt
# findings. It focuses on deterministic, security-relevant signals extracted
# from the AndroidManifest.xml and signing metadata.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
import json
import xml.etree.ElementTree as ET

from main.schema.normalize import Finding


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}


def parse_androguard(raw_file: Path):
    """
    Parse Androguard analysis output and generate normalized findings.

    Input:
    - raw_file: androguard.json produced by the Androguard runner

    Output:
    - List of Finding objects representing security-relevant Android issues
    """

    findings = []
    timestamp = datetime.now(timezone.utc)

    data = json.loads(raw_file.read_text(encoding="utf-8"))

    # --------------------------------------------------
    # AndroidManifest.xml analysis (axml)
    # --------------------------------------------------
    axml = data.get("axml")
    if axml:
        try:
            root = ET.fromstring(axml)
        except ET.ParseError as e:
            raise RuntimeError(f"Androguard parser error: invalid AXML: {e}")

        # Application-level flags
        app = root.find("application")
        if app is not None:
            if app.attrib.get(ANDROID_NS + "debuggable") == "true":
                findings.append(
                    Finding(
                        asset="AndroidManifest.xml",
                        title="Application is debuggable",
                        tool="androguard",
                        kind="finding",
                        severity="medium",
                        timestamp=timestamp,
                        evidence_path=str(raw_file),
                    )
                )

            if app.attrib.get(ANDROID_NS + "usesCleartextTraffic") == "true":
                findings.append(
                    Finding(
                        asset="AndroidManifest.xml",
                        title="Cleartext traffic is permitted",
                        tool="androguard",
                        kind="finding",
                        severity="medium",
                        timestamp=timestamp,
                        evidence_path=str(raw_file),
                    )
                )

        # Permissions
        for perm in root.findall("uses-permission"):
            name = perm.attrib.get(ANDROID_NS + "name")
            if name in DANGEROUS_PERMISSIONS:
                findings.append(
                    Finding(
                        asset=name,
                        title="Dangerous Android permission requested",
                        tool="androguard",
                        kind="finding",
                        severity="medium",
                        timestamp=timestamp,
                        evidence_path=str(raw_file),
                        metadata={"permission": name},
                    )
                )

        # Exported components
        for elem in root.iter():
            tag = elem.tag.split("}")[-1]
            if tag not in {"activity", "service", "receiver", "provider"}:
                continue

            if elem.attrib.get(ANDROID_NS + "exported") == "true":
                name = elem.attrib.get(ANDROID_NS + "name", "unknown")
                findings.append(
                    Finding(
                        asset=name,
                        title=f"Exported Android component ({tag})",
                        tool="androguard",
                        kind="asset",
                        timestamp=timestamp,
                        evidence_path=str(raw_file),
                        metadata={"component": tag},
                    )
                )

    # --------------------------------------------------
    # Signing analysis
    # --------------------------------------------------
    sign = data.get("sign", "")
    if sign:
        if "Is signed v1: False" in sign:
            findings.append(
                Finding(
                    asset="APK",
                    title="APK is not v1 signed",
                    tool="androguard",
                    kind="finding",
                    severity="low",
                    timestamp=timestamp,
                    evidence_path=str(raw_file),
                )
            )

        if "Is signed v2: False" in sign:
            findings.append(
                Finding(
                    asset="APK",
                    title="APK is not v2 signed",
                    tool="androguard",
                    kind="finding",
                    severity="low",
                    timestamp=timestamp,
                    evidence_path=str(raw_file),
                )
            )

    return findings