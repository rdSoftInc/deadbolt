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

from main.core.tool_manifest import get_tool_config_by_image

# Regular expression used to extract semantic version strings
VERSION_RE = re.compile(r"(?:v)?\d+\.\d+(?:\.\d+)?")

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

    config = get_tool_config_by_image(image)
    if config and config.version_detection == "configured":
        if not config.managed and ":" in image:
            tag = image.rsplit(":", 1)[1]
            if tag and tag != "latest":
                return tag.lstrip("v")
        return config.display_version

    if config and config.version_detection == "image_label":
        try:
            result = subprocess.run(
                [
                    "docker",
                    "image",
                    "inspect",
                    image,
                    "--format",
                    '{{index .Config.Labels "io.deadbolt.tool.version"}}',
                ],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            label_version = result.stdout.strip().lstrip("v")
            if result.returncode == 0 and label_version and label_version != "<no value>":
                if config.version_type == "commit" and len(label_version) == 40:
                    return label_version[:7]
                return label_version
        except (OSError, subprocess.SubprocessError):
            pass

    # -------------------------------
    # Generic CLI-based detection
    # -------------------------------

    version_args = config.version_args if config else [
        ["-version"],
        ["--version"],
        ["version"],
    ]

    for args in version_args:
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", image, *args],
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
