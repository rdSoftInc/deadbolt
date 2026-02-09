# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file version_cache.py
# @brief Persistent cache for tool version resolution.
#
# This module implements a lightweight, file-backed cache for storing resolved
# installed and latest tool versions. The cache is used to reduce repeated
# external lookups (e.g. GitHub API calls) and to keep UI version display
# responsive during scans.
#
# Cache entries are validated using a time-to-live (TTL) and basic sanity
# checks to avoid propagating placeholder or invalid values.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
import json

# Cache location and defaults
CACHE_DIR = Path.home() / ".deadbolt"
CACHE_FILE = CACHE_DIR / "version_cache.json"
DEFAULT_TTL = 3600  # 1 hour

# Values considered invalid for caching purposes
INVALID_VALUES = {"unknown", "checking…", "-", "rolling", None}


def load_cache() -> dict:
    """
    Load the version cache from disk.

    If the cache file does not exist, a new cache structure with default
    values is returned.
    """
    if not CACHE_FILE.exists():
        return {
            "schema": 1,
            "ttl_seconds": DEFAULT_TTL,
            "tools": {},
        }

    return json.loads(CACHE_FILE.read_text(encoding="utf-8"))


def save_cache(cache: dict) -> None:
    """
    Persist the version cache to disk.

    The cache directory is created if it does not already exist.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(
        json.dumps(cache, indent=2),
        encoding="utf-8",
    )


def is_fresh(entry: dict, ttl: int) -> bool:
    """
    Determine whether a cache entry is still fresh.

    Freshness is based on the entry's timestamp and the configured TTL.
    """
    try:
        ts = datetime.fromisoformat(entry["checked_at"])
    except Exception:
        return False

    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return age < ttl


def is_valid(value) -> bool:
    """
    Determine whether a cached value is valid.

    Placeholder or sentinel values are treated as invalid and will trigger
    re-resolution.
    """
    return value not in INVALID_VALUES


def invalidate_version(image: str) -> None:
    """
    Remove a cached version entry for a specific image.

    This forces version re-resolution on the next lookup.
    """
    cache = load_cache()
    tools = cache.get("tools", {})

    if image in tools:
        del tools[image]
        save_cache(cache)


def get_cached_versions(
    *,
    image: str,
    resolve_installed,
    resolve_latest,
) -> tuple[str, str]:
    """
    Retrieve cached installed and latest versions for a tool image.

    The cache is used only if:
    - an entry exists
    - the entry is fresh
    - both installed and latest values are valid

    Otherwise, the provided resolver callables are invoked to re-resolve
    versions, and the cache is updated accordingly.
    """
    cache = load_cache()
    ttl = cache.get("ttl_seconds", DEFAULT_TTL)
    tools = cache.setdefault("tools", {})

    entry = tools.get(image)

    # Use cache only if entry is fresh and values are valid
    if (
        entry
        and is_fresh(entry, ttl)
        and is_valid(entry.get("installed"))
        and is_valid(entry.get("latest"))
    ):
        return entry["installed"], entry["latest"]

    # Re-resolve versions
    installed = resolve_installed(image)
    latest = resolve_latest(image)

    tools[image] = {
        "installed": installed,
        "latest": latest,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    save_cache(cache)
    return installed, latest