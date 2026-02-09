# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file version.py
# @brief Resolve installed tool versions from container images.
#
# This module provides a best-effort mechanism for determining the installed
# version of a tool by executing its container image and inspecting version
# output. It includes explicit overrides for tools that do not expose a
# reliable CLI version flag.
#
# Results are cached to avoid repeated container execution during a run.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import subprocess
import re
from functools import lru_cache
from typing import Optional

# Regular expression used to extract semantic version strings
VERSION_RE = re.compile(r"(?:v)?\d+\.\d+\.\d+")

# Common CLI flags used to query tool versions
VERSION_FLAGS = ["-version", "--version", "version"]


@lru_cache(maxsize=32)
def get_tool_version(image: str) -> str:
    """
    Resolve the installed version of a tool from its container image.

    This function attempts to determine the tool version by running the
    container image with common version flags and parsing the output.
    For tools that do not expose a reliable CLI version, explicit mappings
    are used as a fallback.

    Resolution is best-effort: failures return "unknown" and do not affect
    execution.
    """

    # -------------------------------
    # Explicit version mappings
    # -------------------------------

    # MobSF does not expose a stable CLI version
    if image == "opensecurity/mobile-security-framework-mobsf":
        return "4.4.5"

    # graphql-cop does not reliably expose version information
    if image == "deadbolt-graphql-cop":
        return "1.15"

    # hakrawler version is not consistently exposed via CLI
    if image == "deadbolt-hakrawler":
        return "2.1"

    # ParamSpider does not provide a standard version flag
    if image == "deadbolt-paramspider":
        return "1.0.1"

    # waybackurls version is static and not printed via CLI
    if image == "deadbolt-waybackurls":
        return "0.1.0"

    # -------------------------------
    # Generic CLI-based detection
    # -------------------------------

    for flag in VERSION_FLAGS:
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", image, flag],
                capture_output=True,
                text=True,
                timeout=8,
            )
        except Exception:
            continue

        output = (result.stdout or "") + (result.stderr or "")
        match = VERSION_RE.search(output)
        if match:
            return match.group(0).lstrip("v")

    return "unknown"