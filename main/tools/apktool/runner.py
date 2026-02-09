# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief apktool execution wrapper.
#
# This module defines the execution logic for apktool using a containerized
# runtime. apktool is used for static Android analysis to decode application
# resources and the AndroidManifest.xml for configuration and attack surface
# inspection.
#
# This module is intentionally execution-only. It does not interpret or analyze
# decoded output; parsing and normalization are handled by a dedicated parser.
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

    # Use a temporary directory to isolate decoded artifacts
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)

        # Execute apktool inside the container
        subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{apk.resolve()}:/input.apk",
                "-v", f"{tmp_dir.resolve()}:/out",
                "deadbolt-apktool",
                "d", "/input.apk",
                "-o", "/out",
                "-f",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

        # Validate expected primary artifact
        manifest = tmp_dir / "AndroidManifest.xml"
        if not manifest.exists():
            raise RuntimeError(
                "apktool execution failed: AndroidManifest.xml not found"
            )

        # Copy the manifest to the output directory for the parser
        output.parent.mkdir(parents=True, exist_ok=True)
        manifest_output = output.parent / "AndroidManifest.xml"
        shutil.copy2(manifest, manifest_output)

        # Collect a normalized list of decoded files for downstream analysis
        files = [
            str(p.relative_to(tmp_dir))
            for p in tmp_dir.rglob("*")
            if p.is_file()
        ]

        data = {
            "manifest": "AndroidManifest.xml",
            "files": files,
        }

        # Persist normalized execution output
        output.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8",
        )