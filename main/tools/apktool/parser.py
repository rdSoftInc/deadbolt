# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief apktool output parser for Android static configuration analysis.
#
# This module parses apktool output to extract security-relevant configuration
# and attack surface signals from the AndroidManifest.xml. Findings generated
# here focus on exported components and application-level security flags.
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


def _bool_attr(elem, name: str):
    """
    Normalize boolean Android manifest attributes.
    """
    value = elem.attrib.get(ANDROID_NS + name)
    if value is None:
        return None
    return value.lower() == "true"


def parse_apktool(raw_file: Path):
    """
    Parse apktool execution output and generate normalized findings.

    Input:
    - raw_file: apktool.json produced by the apktool runner
    
    Note:
    The apktool.json file only contains metadata about decoded artifacts.
    The actual AndroidManifest.xml is expected to be in the same directory
    as the apktool.json file (or a subdirectory if specified).

    Output:
    - List of Finding objects describing Android configuration issues
      and exposed application components
    """

    findings = []
    timestamp = datetime.now(timezone.utc)

    data = json.loads(raw_file.read_text(encoding="utf-8"))

    # The manifest path is relative to the raw_file directory
    # The apktool.json is in: raw_dir/apktool/apktool.json
    # The decoded AndroidManifest.xml is in: raw_dir/apktool/AndroidManifest.xml
    # So we need to look in the same directory as the JSON file
    manifest_relative = data.get("manifest", "AndroidManifest.xml")
    manifest_path = raw_file.parent / manifest_relative

    if not manifest_path.exists():
        raise RuntimeError(
            "apktool parser error: AndroidManifest.xml not found "
            f"at {manifest_path}. Checked: {raw_file.parent}"
        )

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as e:
        raise RuntimeError(
            f"apktool parser error: Failed to parse AndroidManifest.xml: {e}"
        )

    application = root.find("application")
    if application is not None:
        # Debuggable application
        if _bool_attr(application, "debuggable") is True:
            findings.append(
                Finding(
                    asset="AndroidManifest.xml",
                    title="Application is debuggable",
                    tool="apktool",
                    kind="finding",
                    severity="medium",
                    timestamp=timestamp,
                    evidence_path=str(manifest_path),
                )
            )

        # Cleartext traffic
        if _bool_attr(application, "usesCleartextTraffic") is True:
            findings.append(
                Finding(
                    asset="AndroidManifest.xml",
                    title="Cleartext traffic is permitted",
                    tool="apktool",
                    kind="finding",
                    severity="medium",
                    timestamp=timestamp,
                    evidence_path=str(manifest_path),
                )
            )

    # Exported components
    for component in root.iter():
        tag = component.tag.split("}")[-1]

        if tag not in {"activity", "service", "receiver", "provider"}:
            continue

        exported = _bool_attr(component, "exported")
        name = component.attrib.get(ANDROID_NS + "name")

        if exported is True and name:
            findings.append(
                Finding(
                    asset=name,
                    title=f"Exported Android component ({tag})",
                    tool="apktool",
                    kind="asset",
                    timestamp=timestamp,
                    evidence_path=str(manifest_path),
                    metadata={
                        "component": tag,
                        "exported": True,
                    },
                )
            )

    return findings