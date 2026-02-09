# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file state.py
# @brief Persistent execution state helpers.
#
# This module provides helpers for hashing inputs and persisting per-run
# execution state used to support resume and skip semantics.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import json
import hashlib
from pathlib import Path


def hash_file(path: Path) -> str:
    """
    Compute a SHA-256 hash of a file.

    Used to determine whether a tool's input has changed between runs.
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_state(path: Path) -> dict:
    """
    Load execution state from disk.

    If no state file exists, a default schema is returned.
    """
    if not path.exists():
        return {"schema": 1, "tools": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path: Path, state: dict) -> None:
    """
    Persist execution state to disk.
    """
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")