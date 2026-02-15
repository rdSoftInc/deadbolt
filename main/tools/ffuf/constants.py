# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file constants.py
# @brief Central configuration for ffuf runtime.
#
# This module defines runtime constants for ffuf execution.
# All ffuf-specific paths and image names must be defined here
# to ensure single-source-of-truth configuration.
#
# -----------------------------------------------------------------------------

from pathlib import Path

# Docker image name
FFUF_IMAGE = "deadbolt-ffuf"

# Deterministic wordlist (shallow scan)
FFUF_WORDLIST_HOST_PATH = Path("wordlists/shallow.txt")

# Container mount path
FFUF_WORDLIST_CONTAINER_PATH = "/wordlists/shallow.txt"

# Output file name
FFUF_OUTPUT_NAME = "ffuf.json"