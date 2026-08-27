# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file resume.py
# @brief Run directory resolution and resume handling.
#
# This module defines the logic for resolving the base output directory
# for Deadbolt runs, supporting both fresh executions and resumable runs.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime
import json


def resolve_scope_snapshot(run_dir: Path) -> Path | None:
    """Return the immutable, run-owned scope snapshot recorded for a run.

    Completed runs normally record the snapshot in ``meta.json`` while an
    interrupted run may only have the earlier ``state.json`` record. Never
    accept a pointer outside the run directory: resume must not broaden or
    replace authorization through a tampered state file.
    """

    run_dir = run_dir.resolve()
    references: list[str] = []
    for name in ("meta.json", "state.json"):
        path = run_dir / name
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        reference = (
            payload.get("scope_snapshot")
            if name == "meta.json"
            else (payload.get("scope") or {}).get("snapshot")
        )
        if reference:
            references.append(str(reference))

    for reference in references:
        candidate = Path(reference)
        candidate = candidate if candidate.is_absolute() else run_dir / candidate
        try:
            resolved = candidate.resolve()
            resolved.relative_to(run_dir)
        except (OSError, RuntimeError, ValueError):
            continue
        if resolved.is_file():
            return resolved

    # Legacy interrupted runs may have created the immutable snapshot before
    # state began recording its path. A single run-owned candidate is
    # unambiguous; multiple files must never be guessed between.
    candidates = sorted((run_dir / "scope").glob("*.yaml"))
    if len(candidates) == 1 and candidates[0].is_file():
        return candidates[0].resolve()
    return None


def _resolve_run_base(resume_from: Path | None) -> Path:
    """
    Resolve the run base directory.

    Fresh run:
        outputs/run_YYYYMMDD_HHMMSS

    Resume run:
        outputs/run_xxx/

    Resume semantics are directory-only to ensure state consistency.
    """
    if resume_from is None:
        run_id = datetime.now().strftime("run_%Y%m%d_%H%M%S")
        return (Path("outputs") / run_id).resolve()

    resume_from = resume_from.resolve()

    # Directory-only resume semantics
    if (
        resume_from.is_dir()
        and resume_from.name.startswith("run_")
        and resume_from.parent.name == "outputs"
    ):
        return resume_from

    raise RuntimeError(
        "Resume path must be an outputs/run_xxx/ directory"
    )
