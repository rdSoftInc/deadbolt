# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file latest_version.py
# @brief Resolve latest upstream tool versions from GitHub.
#
# This module provides a helper for resolving the latest released version of
# a tool based on its associated GitHub repository. Version resolution is
# best-effort and intended for informational display only; failures do not
# affect execution.
#
# Results are cached to minimize external requests during a single run.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import requests
from functools import lru_cache


# Mapping of Deadbolt container images to upstream GitHub repositories
REPO_MAP = {
    # Discovery
    "deadbolt-subfinder": "projectdiscovery/subfinder",
    "deadbolt-dnsx": "projectdiscovery/dnsx",
    "deadbolt-httpx": "projectdiscovery/httpx",
    "deadbolt-apktool": "iBotPeaches/Apktool",
    "deadbolt-androguard": "androguard/androguard",

    # Enumeration
    "deadbolt-katana": "projectdiscovery/katana",
    "deadbolt-gau": "lc/gau",
    "deadbolt-ffuf": "ffuf/ffuf",
    "deadbolt-hakrawler": "hakluke/hakrawler",
    "deadbolt-waybackurls": "tomnomnom/waybackurls",

    # Vulnerability / Analysis
    "deadbolt-nuclei": "projectdiscovery/nuclei",
    "deadbolt-paramspider": "devanshbatham/ParamSpider",
    "deadbolt-graphql-cop": "dolevf/graphql-cop",
    "deadbolt-jadx": "skylot/jadx",
    "opensecurity/mobile-security-framework-mobsf":"MobSF/Mobile-Security-Framework-MobSF",
}


@lru_cache(maxsize=32)
def get_latest_version(image: str) -> str | None:
    """
    Resolve the latest upstream release version for a tool image.

    This function maps a Deadbolt container image to its corresponding
    GitHub repository and queries the GitHub Releases API for the latest
    published version.

    The result is cached to reduce API usage. Any network or API failures
    return None and are treated as non-fatal.
    """
    repo = REPO_MAP.get(image)
    if not repo:
        return None

    url = f"https://api.github.com/repos/{repo}/releases/latest"

    try:
        r = requests.get(url, timeout=5)
    except Exception:
        return None

    if r.status_code != 200:
        return None

    tag = r.json().get("tag_name")
    return tag.lstrip("v") if tag else None