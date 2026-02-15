# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file latest_version.py
# @brief Resolve latest upstream tool versions from GitHub.
#
# This module provides helpers for resolving the latest released version of
# a tool based on its associated GitHub repository. If a repository does not
# publish GitHub releases (e.g., LinkFinder), the resolver falls back to the
# latest commit SHA from the default branch.
#
# Version resolution is best-effort and informational only.
# Failures are non-fatal and return None.
#
# Results are cached to minimize external requests during a single run.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import requests
from functools import lru_cache


# -----------------------------------------------------------------------------
# Repository Mapping
# -----------------------------------------------------------------------------

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
    "deadbolt-linkfinder": "GerbenJavado/LinkFinder",  # Added

    # Vulnerability / Analysis
    "deadbolt-nuclei": "projectdiscovery/nuclei",
    "deadbolt-schemathesis": "schemathesis/schemathesis",
    "deadbolt-paramspider": "devanshbatham/ParamSpider",
    "deadbolt-graphql-cop": "dolevf/graphql-cop",
    "deadbolt-jadx": "skylot/jadx",
    "opensecurity/mobile-security-framework-mobsf":
        "MobSF/Mobile-Security-Framework-MobSF",
}


# -----------------------------------------------------------------------------
# GitHub API Helpers
# -----------------------------------------------------------------------------

def _get_latest_release(repo: str) -> str | None:
    """
    Attempt to resolve latest GitHub release tag.
    """
    url = f"https://api.github.com/repos/{repo}/releases/latest"

    try:
        r = requests.get(url, timeout=5)
    except Exception:
        return None

    if r.status_code != 200:
        return None

    tag = r.json().get("tag_name")
    return tag.lstrip("v") if tag else None


def _get_latest_commit(repo: str) -> str | None:
    """
    Fallback resolver: fetch latest commit SHA from default branch.
    Returns short SHA (7 chars) for display.
    """
    url = f"https://api.github.com/repos/{repo}/commits"

    try:
        r = requests.get(url, timeout=5)
    except Exception:
        return None

    if r.status_code != 200:
        return None

    commits = r.json()
    if not isinstance(commits, list) or not commits:
        return None

    sha = commits[0].get("sha")
    return sha[:7] if sha else None


# -----------------------------------------------------------------------------
# Public Resolver
# -----------------------------------------------------------------------------

@lru_cache(maxsize=32)
def get_latest_version(image: str) -> str | None:
    """
    Resolve latest upstream version for a tool image.

    Resolution order:
    1. Latest GitHub Release (preferred)
    2. Latest commit SHA (fallback)
    3. None if resolution fails

    This function is informational only and never raises.
    """

    repo = REPO_MAP.get(image)
    if not repo:
        return None

    # Attempt release first
    release = _get_latest_release(repo)
    if release:
        return release

    # Fallback to commit (for repos without releases, e.g., LinkFinder)
    return _get_latest_commit(repo)