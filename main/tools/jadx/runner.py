# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief jadx execution wrapper for Android static analysis.
#
# This module defines the execution logic for jadx. It decompiles an Android
# APK and performs comprehensive static analysis to extract URLs, secrets,
# API patterns, and manifest security data from source-like files and bytecode.
#
# Extraction strategy:
# - Decompiles APK using jadx
# - Scans text files (.java, .kt, .xml) for URLs and secrets
# - Analyzes Smali bytecode files for string constants and API calls
# - Extracts AndroidManifest.xml for security configuration
# - Applies filters to reduce framework noise
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import json
import subprocess
import re
from typing import Set, Tuple


# File types considered for static string analysis
TEXT_EXTENSIONS = {
    ".java", ".kt", ".xml", ".txt", ".json", ".yaml", ".yml",
    ".properties", ".gradle", ".smali",
}

# Maximum file size to scan (to avoid large binaries)
MAX_FILE_SIZE = 512 * 1024  # 512 KB

# Patterns for extracting secret values
SECRET_VALUE_PATTERNS = {
    "api_key": re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9\-_./+=]+)["\']', re.IGNORECASE),
    "token": re.compile(r'(?:token|access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']([a-zA-Z0-9\-_./+=]+)["\']', re.IGNORECASE),
    "password": re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', re.IGNORECASE),
    "secret": re.compile(r'(?:secret|secret_key)\s*[:=]\s*["\']([a-zA-Z0-9\-_./+=]+)["\']', re.IGNORECASE),
    "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
}

# Smali patterns
SMALI_PATTERNS = {
    "const_string": re.compile(r'const-string\s+v\d+,\s*"([^"]*)"'),
    "http_url": re.compile(r'"(https?://[^"]*)"'),
}

# URL extraction pattern
URL_PATTERN = re.compile(r'(https?://[^\s"\'<>\)\];]+)')


def _extract_urls(content: str) -> Set[str]:
    """Extract URLs from content"""
    urls = set()
    for match in URL_PATTERN.finditer(content):
        url = match.group(1)
        while url and url[-1] in '.,:;)]}>\'"':
            url = url[:-1]
        if len(url) >= 10 and "schemas.android.com" not in url:
            urls.add(url)
    return urls


def _extract_secrets(content: str) -> Set[str]:
    """Extract potential secrets using pattern matching"""
    secrets = set()
    for pattern_name, pattern in SECRET_VALUE_PATTERNS.items():
        for match in pattern.finditer(content):
            try:
                value = match.group(1) if match.groups() else match.group(0)
                if len(value) >= 8 and not value.startswith(("kotlin.", "android.", "com.google")):
                    secrets.add(value)
            except (IndexError, AttributeError):
                continue
    return secrets


def _extract_manifest_data(manifest_path: Path) -> dict:
    """Extract security data from AndroidManifest.xml"""
    manifest_data = {
        "permissions": [],
        "debuggable": False,
        "allow_backup": False,
    }
    
    try:
        content = manifest_path.read_text(errors="ignore")
    except Exception:
        return manifest_data
    
    perm_pattern = re.compile(r'<uses-permission\s+android:name="([^"]+)"')
    manifest_data["permissions"] = perm_pattern.findall(content)
    manifest_data["debuggable"] = 'android:debuggable="true"' in content
    manifest_data["allow_backup"] = 'android:allowBackup="true"' in content
    
    return manifest_data


def run_jadx(apk: Path, output: Path):
    """
    Execute jadx against an Android APK.

    Consumes:
      - apk (Android application package)

    Produces:
      - JSON output containing extracted URLs, strings, and file inventory

    Strategy:
      - Decompile APK using jadx
      - Scan text-like files for URLs and secret-like strings
      - Analyze smali bytecode files
      - Extract manifest security data
      - Apply filters to reduce noise
    """

    out_dir = output.parent / "jadx_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------
    # Run jadx decompiler
    # -------------------------------
    subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{apk.resolve()}:/input.apk",
            "-v", f"{out_dir.resolve()}:/out",
            "deadbolt-jadx",
            "-d", "/out",
            "/input.apk",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if not out_dir.exists() or not any(out_dir.iterdir()):
        raise RuntimeError("jadx produced no output")

    findings = {
        "urls": set(),
        "strings": set(),
        "files": [],
        "manifest": {},
    }

    # -------------------------------
    # Static string extraction
    # -------------------------------
    for file in out_dir.rglob("*"):
        if not file.is_file():
            continue

        # Handle manifest specially
        if file.name == "AndroidManifest.xml":
            findings["manifest"] = _extract_manifest_data(file)
            continue

        if file.suffix.lower() not in TEXT_EXTENSIONS:
            continue

        if file.stat().st_size > MAX_FILE_SIZE:
            continue

        findings["files"].append(str(file.relative_to(out_dir)))

        try:
            content = file.read_text(errors="ignore")
        except Exception:
            continue

        # Extract URLs
        findings["urls"].update(_extract_urls(content))
        
        # Extract secrets using pattern matching
        findings["strings"].update(_extract_secrets(content))

    # -------------------------------
    # Persist structured output
    # -------------------------------
    output.write_text(
        json.dumps(
            {
                "urls": sorted(list(findings["urls"])),
                "strings": sorted(list(findings["strings"])),
                "files": findings["files"],
                "manifest": findings["manifest"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )