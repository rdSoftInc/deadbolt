# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief jadx output parser for Android static analysis.
#
# This module parses structured output produced by jadx analysis and
# normalizes extracted URLs and potential secrets into Deadbolt Finding
# objects. Results are filtered to reduce framework noise and false
# positives.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
import json
from typing import List

from main.schema.normalize import Finding


# Android framework namespace prefixes to ignore
ANDROID_NAMESPACE_PREFIXES = (
    "http://schemas.android.com",
)

# Keywords commonly associated with secrets or credentials
SECRET_KEYWORDS = (
    "api_key",
    "apikey",
    "secret",
    "token",
    "access_key",
    "auth",
    "password",
)


def _is_real_url(u: str) -> bool:
    """
    Determine whether a string represents a meaningful external URL.

    Filters out Android framework namespaces and non-HTTP(S) values.
    """
    if not (u.startswith("http://") or u.startswith("https://")):
        return False

    for prefix in ANDROID_NAMESPACE_PREFIXES:
        if u.startswith(prefix):
            return False

    return True


def _looks_like_secret(s: str) -> bool:
    """
    Heuristically determine whether a string resembles a hardcoded secret.

    The check is intentionally conservative to reduce false positives.
    """
    s_low = s.lower()

    # Must contain a secret-related keyword
    if not any(k in s_low for k in SECRET_KEYWORDS):
        return False

    # Avoid extremely short or meaningless values
    if len(s) < 8:
        return False

    # Exclude obvious framework noise
    if s_low.startswith("kotlin.") or s_low.startswith("android."):
        return False

    return True


def parse_jadx(raw_file: Path) -> List[Finding]:
    """
    Parse jadx JSON output into normalized findings.

    The parser extracts:
    1. Hardcoded URLs → attack surface assets
    2. Potential secrets or tokens → high-severity findings

    Filters are applied to reduce framework artifacts and false positives.
    """
    findings: List[Finding] = []
    timestamp = datetime.now(timezone.utc)

    data = json.loads(raw_file.read_text(encoding="utf-8"))

    # --------------------------------------------------
    # 1. URLs → attack surface
    # --------------------------------------------------
    for url in set(filter(_is_real_url, data.get("urls", []))):
        findings.append(
            Finding(
                asset=url,
                title="Hardcoded URL in Android APK",
                tool="jadx",
                kind="asset",

                timestamp=timestamp,
                evidence_path=str(raw_file),

                metadata={
                    "source": "jadx",
                    "type": "url",
                },
            )
        )

    # --------------------------------------------------
    # 2. Secrets / tokens → vulnerabilities
    # --------------------------------------------------
    for s in set(filter(_looks_like_secret, data.get("strings", []))):
        findings.append(
            Finding(
                asset=s,
                title="Potential hardcoded secret in Android APK",
                tool="jadx",
                kind="finding",

                severity="high",
                occurrences=1,

                timestamp=timestamp,
                evidence_path=str(raw_file),

                metadata={
                    "source": "jadx",
                    "confidence": "medium",
                    "category": "secret",
                },
            )
        )

    return findings