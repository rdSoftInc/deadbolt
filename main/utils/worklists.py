# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file worklists.py
# @brief Worklist generation and merging helpers.
#
# This module manages plaintext worklists that represent intermediate
# artifacts passed between discovery, enumeration, and vulnerability phases.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from typing import Iterable, List
from main.schema.normalize import Finding


def _write_or_merge_worklist_txt(path: Path, items: Iterable[str]) -> None:
    """
    Append new items to a plaintext worklist file, avoiding duplicates.

    Existing entries are preserved; only previously unseen items are appended.
    """
    existing = set()
    if path.exists():
        existing = set(
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )

    new_items = []
    for x in items:
        x = (x or "").strip()
        if x and x not in existing:
            existing.add(x)
            new_items.append(x)

    if new_items:
        with path.open("a", encoding="utf-8") as f:
            for x in new_items:
                f.write(x + "\n")


def _findings_to_work_items(
    output_type: str,
    findings: List[Finding],
) -> List[str]:
    """
    Convert normalized findings into worklist items for the next phase.

    Mapping:
      - assets   -> Finding.asset
      - paths    -> Finding.asset
      - findings -> no downstream worklist (empty)
    """
    if output_type in ("assets", "paths"):
        return [f.asset for f in findings]
    return []