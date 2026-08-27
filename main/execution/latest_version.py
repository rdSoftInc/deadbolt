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

import re

import requests
from functools import lru_cache

from main.core.tool_manifest import get_tool_config_by_image, load_tool_manifest


# -----------------------------------------------------------------------------
# Repository Mapping
# -----------------------------------------------------------------------------

REPO_MAP = {
    config.image.split(":", 1)[0]: config.repository
    for config in load_tool_manifest().tools.values()
}

# These images are built from an immutable source commit rather than a release
# artifact. Comparing their installed commit to a release tag would always
# produce a false update warning.
COMMIT_TRACKED_IMAGES = {
    config.image.split(":", 1)[0]
    for config in load_tool_manifest().tools.values()
    if config.version_type == "commit"
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


def _get_latest_nmap_release() -> str | None:
    """Resolve the stable source release advertised by nmap.org."""

    try:
        response = requests.get("https://nmap.org/download.html", timeout=5)
    except Exception:
        return None
    if response.status_code != 200:
        return None
    versions = re.findall(r"nmap-(\d+\.\d+)\.tar\.bz2", response.text)
    return versions[0] if versions else None


def _get_latest_commit(repo: str, *, short: bool = True) -> str | None:
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
    if not sha:
        return None
    return sha[:7] if short else sha


@lru_cache(maxsize=32)
def get_latest_pin(image: str) -> str | None:
    """Resolve the complete value suitable for writing back to the manifest."""

    config = get_tool_config_by_image(image)
    if not config:
        return None
    if config.source == "nmap":
        return _get_latest_nmap_release()
    if config.version_type == "commit":
        return _get_latest_commit(config.repository, short=False)
    return _get_latest_release(config.repository)


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

    config = get_tool_config_by_image(image)
    if not config:
        return None

    if config.source == "nmap":
        return _get_latest_nmap_release()

    if config.version_type == "commit":
        return _get_latest_commit(config.repository)

    # Attempt release first
    release = _get_latest_release(config.repository)
    if release:
        return release

    # Fallback to commit (for repos without releases, e.g., LinkFinder)
    return _get_latest_commit(config.repository)
