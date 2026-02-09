# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file metadata.py
# @brief Metadata persistence utilities for Deadbolt scan runs.
#
# This module provides helper functions for writing structured metadata
# describing a Deadbolt scan execution. The generated metadata captures
# timing information, targets, tool versions, and execution errors, and is
# stored alongside scan outputs for traceability and later analysis.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from datetime import datetime, timezone
from pathlib import Path
import json
from typing import Dict, Optional


def write_metadata(
    *,
    base_dir: Path,
    run_id: str,
    targets_file: Path,
    tools: Dict[str, Dict[str, str]],
    started_at: datetime,
    finished_at: datetime,
    domain: str,
    deadbolt_version: str = "0.1.0",
    errors: Optional[Dict[str, str]] = None,
):
    """
    Write execution metadata for a Deadbolt scan run.

    This function serializes run-level metadata to a `meta.json` file in the
    specified base directory. The metadata captures timing information,
    execution context, tool details, and any errors encountered during
    execution.

    All timestamps are normalized to UTC and stored in ISO 8601 format to
    ensure consistency across environments.
    """
    meta = {
        "run_id": run_id,
        "domain": domain,
        "started_at": started_at.astimezone(timezone.utc).isoformat(),
        "finished_at": finished_at.astimezone(timezone.utc).isoformat(),
        "targets_file": str(targets_file),
        "deadbolt_version": deadbolt_version,
        "tools": tools,
        "errors": errors or {},
    }

    meta_path = base_dir / "meta.json"
    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)