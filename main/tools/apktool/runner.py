# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief apktool execution wrapper for Android static analysis.
#
# This module defines the execution logic for apktool using a containerized
# runtime. apktool is used for static Android analysis to decode application
# resources and the AndroidManifest.xml for configuration and attack surface
# inspection.
#
# Execution behavior:
# - The APK is decoded using apktool inside a containerized environment.
# - Decoding output is written to a temporary directory.
# - The AndroidManifest.xml is copied to the output directory.
# - High-level structural metadata (manifest presence and file list)
#   is persisted for downstream parsing.
# - File statistics (total files, smali files, xml files) are collected.
#
# This module performs no semantic analysis. Its responsibility is limited
# to deterministic tool execution and minimal result materialization.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import json
import subprocess
import tempfile
import shutil


def run_apktool(apk: Path, output: Path) -> None:
    """
    Execute apktool against an Android APK.

    Input:
    - apk: Path to the Android APK file

    Output:
    - apktool.json: normalized execution metadata describing decoded artifacts
    - AndroidManifest.xml: the decoded manifest file for downstream parsing

    Execution behavior:
    - The APK is decoded using apktool inside a containerized environment.
    - Decoding output is written to a temporary directory.
    - The AndroidManifest.xml is copied to the output directory.
    - High-level structural metadata (manifest presence and file list)
      is persisted for downstream parsing.

    This function performs no semantic analysis. Its responsibility is limited
    to deterministic tool execution and minimal result materialization.
    """

    # Validate input
    if not apk.exists():
        raise RuntimeError(f"APK file not found: {apk}")

    # Use a temporary directory to isolate decoded artifacts
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)

        # Execute apktool inside the container
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{apk.resolve()}:/input.apk",
                "-v", f"{tmp_dir.resolve()}:/out",
                "deadbolt-apktool",
                "d", "/input.apk",
                "-o", "/out",
                "-f",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"apktool execution failed: {result.stderr}"
            )

        # Validate expected primary artifact
        manifest = tmp_dir / "AndroidManifest.xml"
        if not manifest.exists():
            raise RuntimeError(
                "apktool execution failed: AndroidManifest.xml not found"
            )

        # Create output directory
        output.parent.mkdir(parents=True, exist_ok=True)

        # Copy the manifest to the output directory for the parser
        manifest_output = output.parent / "AndroidManifest.xml"
        shutil.copy2(manifest, manifest_output)

        # Collect a normalized list of decoded files for downstream analysis
        files = [
            str(p.relative_to(tmp_dir))
            for p in tmp_dir.rglob("*")
            if p.is_file()
        ]

        # Collect metadata about decoded resources
        resources_dir = tmp_dir / "res"
        has_resources = resources_dir.exists() and any(resources_dir.iterdir())

        smali_files = [f for f in files if f.endswith(".smali")]
        xml_files = [f for f in files if f.endswith(".xml")]

        data = {
            "manifest": "AndroidManifest.xml",
            "files": files,
            "statistics": {
                "total_files": len(files),
                "smali_files": len(smali_files),
                "xml_files": len(xml_files),
                "has_resources": has_resources,
            },
        }

        # Persist normalized execution output
        output.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8",
        )