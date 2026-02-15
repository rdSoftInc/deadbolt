# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief jadx output parser for Android static code analysis.
#
# This module parses structured JSON output produced by jadx and normalizes
# extracted code-level artifacts and security findings into Deadbolt
# Finding objects.
#
# Detects:
# - Hardcoded external URLs (attack surface exposure)
# - Dangerous API usage patterns (injection, RCE, deserialization, WebView abuse)
# - Embedded cryptographic materials (private keys, certificates)
# - Hardcoded credentials (JWT, AWS keys, Firebase endpoints)
# - Potential hardcoded secrets
# - Manifest configuration flags (debuggable, backup enabled)
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple, Dict

from main.schema.normalize import Finding


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Android namespace URLs that should not be treated as external endpoints
ANDROID_NAMESPACE_PREFIXES = (
    "http://schemas.android.com",
)

# Keywords commonly associated with secrets or credential exposure
SECRET_KEYWORDS = (
    "api_key", "apikey", "secret", "password",
    "passwd", "pwd", "token", "access_token",
    "refresh_token", "auth", "bearer",
    "private_key", "encryption_key",
    "aws_secret", "aws_access_key",
    "firebase", "service_account",
    "connection_string", "jdbc",
)


# -----------------------------------------------------------------------------
# Precompiled Pattern Definitions
# -----------------------------------------------------------------------------

CRYPTO_PATTERNS = {
    "rsa_private": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "certificate": re.compile(r"-----BEGIN CERTIFICATE-----"),
}

DANGEROUS_API_PATTERNS = {
    "sql_concat": re.compile(r"rawQuery\s*\(.*\+|execSQL\s*\(.*\+", re.I | re.S),
    "runtime_exec": re.compile(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec", re.I),
    "process_builder": re.compile(r"ProcessBuilder\s*\(", re.I),
    "unsafe_deserialization": re.compile(r"ObjectInputStream|readObject\s*\(", re.I),
    "webview_js": re.compile(r"addJavascriptInterface|loadUrl\s*\(\s*['\"]javascript:", re.I),
}

CREDENTIAL_PATTERNS = {
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "firebase_url": re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
}


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

def _is_real_url(u: str) -> bool:
    """
    Determine whether a string represents a meaningful external URL.

    Conditions:
    - Must be HTTP or HTTPS
    - Must not belong to Android XML namespace
    - Must not reference localhost or loopback
    """

    if not isinstance(u, str):
        return False

    if not u.startswith(("http://", "https://")):
        return False

    if any(u.startswith(p) for p in ANDROID_NAMESPACE_PREFIXES):
        return False

    if "localhost" in u or "127.0.0.1" in u:
        return False

    return True


def _detect_crypto_key(s: str) -> Tuple[bool, str]:
    """
    Detect embedded cryptographic material.

    Returns:
        (True, key_type) if detected
        (False, "") otherwise
    """

    for key_type, pattern in CRYPTO_PATTERNS.items():
        if pattern.search(s):
            return True, key_type

    return False, ""


def _detect_dangerous_api(s: str) -> Tuple[bool, str]:
    """
    Detect dangerous API usage patterns.

    Examples:
    - SQL injection via string concatenation
    - Runtime command execution
    - Unsafe deserialization
    - WebView JavaScript injection
    """

    for api_type, pattern in DANGEROUS_API_PATTERNS.items():
        if pattern.search(s):
            return True, api_type

    return False, ""


def _detect_sensitive_credential(s: str) -> Tuple[bool, str]:
    """
    Detect known credential formats.

    Examples:
    - JWT tokens
    - AWS access keys
    - Firebase database URLs
    """

    for cred_type, pattern in CREDENTIAL_PATTERNS.items():
        if pattern.search(s):
            return True, cred_type

    return False, ""


def _looks_like_secret(s: str) -> bool:
    """
    Heuristic detection for potential hardcoded secrets.

    Filters:
    - Length must be reasonable
    - Excludes Android/Kotlin identifiers
    - Excludes structured XML/JSON content
    """

    if not isinstance(s, str):
        return False

    if len(s) < 6 or len(s) > 4096:
        return False

    s_low = s.lower()

    if s_low.startswith(("kotlin.", "android.", "androidx.")):
        return False

    if s_low.startswith(("<", "{", "[")):
        return False

    return any(k in s_low for k in SECRET_KEYWORDS)


# -----------------------------------------------------------------------------
# Main Parser
# -----------------------------------------------------------------------------

def parse_jadx(raw_file: Path) -> List[Finding]:
    """
    Parse jadx JSON output into normalized Deadbolt findings.

    Emits:
    - kind="asset" for hardcoded external URLs
    - kind="finding" for:
        - Dangerous API usage
        - Embedded cryptographic materials
        - Hardcoded credentials
        - Potential secrets
        - Manifest misconfigurations

    Findings are deduplicated using structured keys to ensure
    deterministic and resume-stable output ordering.
    """

    findings: Dict[str, Finding] = {}
    timestamp = datetime.now(timezone.utc)

    data = json.loads(raw_file.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # 1. Hardcoded External URLs (Attack Surface)
    # ------------------------------------------------------------------

    for url in sorted(set(filter(_is_real_url, data.get("urls", [])))):

        findings[f"url:{url}"] = Finding(
            asset=url,
            title="Hardcoded external URL in APK",
            tool="jadx",
            kind="asset",
            timestamp=timestamp,
            evidence_path=str(raw_file),
            metadata={
                "source": "jadx",
                "category": "url",
            },
        )

    # ------------------------------------------------------------------
    # 2. String-Based Static Analysis
    # ------------------------------------------------------------------

    for s in sorted(set(data.get("strings", []))):

        if not isinstance(s, str):
            continue

        # Dangerous API usage
        is_dangerous, api_type = _detect_dangerous_api(s)
        if is_dangerous:
            key = f"api:{api_type}:{s[:100]}"
            findings[key] = Finding(
                asset=s[:200],
                title=f"Dangerous API usage detected ({api_type})",
                tool="jadx",
                kind="finding",
                severity="high",
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata={
                    "source": "jadx",
                    "category": "api_misuse",
                    "api_type": api_type,
                },
            )
            continue

        # Secret heuristics
        if not _looks_like_secret(s):
            continue

        # Cryptographic material
        is_crypto, crypto_type = _detect_crypto_key(s)
        if is_crypto:
            key = f"crypto:{crypto_type}:{s[:100]}"
            findings[key] = Finding(
                asset=s[:200],
                title=f"Embedded cryptographic material ({crypto_type})",
                tool="jadx",
                kind="finding",
                severity="critical",
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata={
                    "source": "jadx",
                    "category": "cryptographic_key",
                },
            )
            continue

        # Known credential formats
        is_sensitive, cred_type = _detect_sensitive_credential(s)
        if is_sensitive:
            key = f"cred:{cred_type}:{s[:100]}"
            findings[key] = Finding(
                asset=s[:200],
                title=f"Hardcoded credential detected ({cred_type})",
                tool="jadx",
                kind="finding",
                severity="critical",
                occurrences=1,
                timestamp=timestamp,
                evidence_path=str(raw_file),
                metadata={
                    "source": "jadx",
                    "category": "hardcoded_credential",
                    "credential_type": cred_type,
                },
            )
            continue

        # Generic secret
        key = f"secret:{s[:100]}"
        findings[key] = Finding(
            asset=s[:200],
            title="Potential hardcoded secret in APK",
            tool="jadx",
            kind="finding",
            severity="high",
            occurrences=1,
            timestamp=timestamp,
            evidence_path=str(raw_file),
            metadata={
                "source": "jadx",
                "category": "secret",
            },
        )

    # ------------------------------------------------------------------
    # 3. Manifest Configuration Cross-Check
    # ------------------------------------------------------------------

    manifest = data.get("manifest", {})

    if manifest.get("debuggable"):
        findings["manifest:debuggable"] = Finding(
            asset="Android APK",
            title="Debuggable configuration detected",
            tool="jadx",
            kind="finding",
            severity="high",
            occurrences=1,
            timestamp=timestamp,
            evidence_path=str(raw_file),
            metadata={
                "source": "jadx",
                "category": "insecure_config",
            },
        )

    if manifest.get("allow_backup"):
        findings["manifest:backup"] = Finding(
            asset="Android APK",
            title="Backup enabled in manifest",
            tool="jadx",
            kind="finding",
            severity="medium",
            occurrences=1,
            timestamp=timestamp,
            evidence_path=str(raw_file),
            metadata={
                "source": "jadx",
                "category": "insecure_config",
            },
        )

    # Deterministic ordering for resume stability
    return sorted(findings.values(), key=lambda f: f.asset)