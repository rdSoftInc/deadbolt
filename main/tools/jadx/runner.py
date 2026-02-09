# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief jadx execution wrapper for Android static analysis.
#
# This module defines the execution logic for jadx. It decompiles an Android
# APK and performs lightweight static analysis to extract URLs and potential
# secrets from source-like files.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import json
import subprocess


# File types considered for static string analysis
TEXT_EXTENSIONS = {
    ".java", ".kt", ".xml", ".txt", ".json", ".yaml", ".yml",
    ".properties", ".gradle",
}

# Maximum file size to scan (to avoid large binaries)
MAX_FILE_SIZE = 512 * 1024  # 512 KB


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
      - Apply size and extension filters to reduce noise
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
        "secrets": set(),
        "files": [],
    }

    # -------------------------------
    # Static string extraction
    # -------------------------------
    for file in out_dir.rglob("*"):
        if not file.is_file():
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

        for line in content.splitlines():
            line = line.strip()

            if "http://" in line or "https://" in line:
                findings["urls"].add(line)

            if any(k in line.lower() for k in ["api_key", "apikey", "token", "secret"]):
                findings["secrets"].add(line)

    # -------------------------------
    # Persist structured output
    # -------------------------------
    output.write_text(
        json.dumps(
            {
                "urls": sorted(findings["urls"]),
                "strings": sorted(findings["secrets"]),
                "files": findings["files"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )