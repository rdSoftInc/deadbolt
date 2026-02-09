# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file targets.py
# @brief Target normalization helpers.
#
# This module provides utilities for extracting canonical domains from
# user-supplied target files containing domains or URLs.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from typing import List
from urllib.parse import urlparse


def _extract_domains_from_targets(targets_file: Path) -> List[str]:
    """
    Extract unique domain names from a targets file.

    The input file may contain:
      - Bare domains
      - Fully-qualified URLs

    Output is a de-duplicated list of lowercase hostnames.
    """
    domains: List[str] = []
    seen = set()

    with targets_file.open("r", encoding="utf-8") as f:
        for line in f:
            t = line.strip()
            if not t:
                continue

            # Prefer URL parsing
            host = urlparse(t).hostname
            if not host:
                # Fallback: treat raw string as a domain
                host = t

            host = host.strip().lower().rstrip(".")
            if host and host not in seen:
                seen.add(host)
                domains.append(host)

    return domains