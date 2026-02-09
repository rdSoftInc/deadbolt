# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief Android domain scan orchestration for Deadbolt.
#
# This module implements the Android scanning pipeline. It coordinates tool
# execution, version detection, resumable state handling, normalization of
# findings, metadata persistence, and final report generation for APK analysis.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict
import json
import threading

from main.core.execution_table import ExecutionTable
from main.core.metadata import write_metadata
from main.schema.normalize import Finding
from main.report.generator import generate_report

from main.execution.latest_version import get_latest_version
from main.execution.version import get_tool_version
from main.execution.version_cache import get_cached_versions

from main.domains.android.runtime_registry import TOOL_RUNTIMES
from main.domains.android.tool_registry import TOOL_REGISTRY
from main.utils.resume import _resolve_run_base
from main.utils.state import load_state, save_state, hash_file


# Ordered execution phases for Android analysis
PHASE_ORDER = ["static", "analysis"]


def run_android(
    *,
    apk_path: Path,
    output_dir: Optional[Path] = None,
) -> None:
    """
    Execute the Android static analysis pipeline.

    This function orchestrates the full lifecycle of an Android scan run:
    - Validates input
    - Initializes output directories and state
    - Detects tool versions asynchronously
    - Executes tools in phase order
    - Normalizes and aggregates findings
    - Persists state and metadata
    - Generates the final report

    The execution is resumable and fault-tolerant: individual tool failures
    do not abort the entire run.
    """

    # -------------------------------
    # Input validation
    # -------------------------------
    if apk_path.suffix.lower() != ".apk":
        raise RuntimeError("Input must be an APK file")

    started_at = datetime.now(timezone.utc)

    # -------------------------------
    # Output directory setup
    # -------------------------------
    base = output_dir.resolve() if output_dir else _resolve_run_base(None)
    base.mkdir(parents=True, exist_ok=True)
    run_id = base.name

    raw_dir = base / "raw"
    norm_dir = base / "normalized"
    raw_dir.mkdir(parents=True, exist_ok=True)
    norm_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------
    # Resume state initialization
    # -------------------------------
    state_file = base / "state.json"
    state = load_state(state_file)
    state.setdefault("schema", 1)
    state.setdefault("tools", {})

    # -------------------------------
    # Execution table initialization
    # -------------------------------
    table = ExecutionTable()
    for tool_name in TOOL_RUNTIMES:
        table.register_tool(tool_name, "detecting…")
    table.start()

    # -------------------------------
    # Asynchronous version detection
    # -------------------------------
    def resolve_versions():
        """
        Resolve installed and latest versions for all tools asynchronously.

        Version resolution runs in background threads to avoid blocking
        execution and continuously updates the execution table UI.
        """
        for spec in TOOL_REGISTRY.values():

            def detect(tool=spec):
                installed, latest = get_cached_versions(
                    image=tool.image,
                    resolve_installed=get_tool_version,
                    resolve_latest=get_latest_version,
                )

                table.versions[tool.name] = installed or "unknown"
                table.latest_versions[tool.name] = latest

                if installed == "unknown" or latest is None:
                    table.update_status[tool.name] = "-"
                elif installed == latest:
                    table.update_status[tool.name] = "latest"
                else:
                    table.update_status[tool.name] = f"→ {latest}"

                table._refresh()

            threading.Thread(target=detect, daemon=True).start()

    threading.Thread(target=resolve_versions, daemon=True).start()

    # -------------------------------
    # Tool execution loop
    # -------------------------------
    all_findings: List[Finding] = []
    tool_errors: Dict[str, str] = {}

    try:
        for phase in PHASE_ORDER:
            for spec in [t for t in TOOL_REGISTRY.values() if t.phase == phase]:

                name = spec.name
                runtime = TOOL_RUNTIMES[name]
                table.tool_started(name)

                # Determine whether this tool can be resumed
                input_hash = hash_file(apk_path)
                tool_state = state["tools"].get(name)

                if (
                    tool_state
                    and tool_state.get("status") == "done"
                    and tool_state.get("input_hash") == input_hash
                ):
                    table.tool_skipped(name)
                    continue

                tool_started_at = datetime.now(timezone.utc)

                raw_tool_dir = raw_dir / name
                raw_tool_dir.mkdir(parents=True, exist_ok=True)
                output = raw_tool_dir / runtime.output_name

                try:
                    # Execute tool and parse findings
                    runtime.runner(apk_path, output)
                    findings = runtime.parser(output)

                except Exception as e:
                    # Tool-level failure handling
                    table.tool_failed(name)
                    tool_errors[name] = str(e)

                    state["tools"][name] = {
                        "status": "failed",
                        "version": table.versions.get(name),
                        "input_hash": input_hash,
                        "started_at": tool_started_at.isoformat(),
                        "finished_at": datetime.now(timezone.utc).isoformat(),
                    }
                    save_state(state_file, state)
                    continue

                # Successful execution path
                table.tool_finished(name, len(findings))
                all_findings.extend(findings)

                out_json = norm_dir / f"{name}.findings.json"
                out_json.write_text(
                    json.dumps(
                        [f.model_dump() for f in findings],
                        indent=2,
                        default=str,
                    ),
                    encoding="utf-8",
                )

                state["tools"][name] = {
                    "status": "done",
                    "version": table.versions.get(name),
                    "input_hash": input_hash,
                    "output_file": str(out_json.relative_to(base)),
                    "started_at": tool_started_at.isoformat(),
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                }
                save_state(state_file, state)

    finally:
        # Ensure the live execution table is always stopped cleanly
        table.stop()

    # -------------------------------
    # Finalization
    # -------------------------------
    finished_at = datetime.now(timezone.utc)

    (norm_dir / "findings.json").write_text(
        json.dumps(
            [f.model_dump() for f in all_findings],
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    write_metadata(
        base_dir=base,
        run_id=run_id,
        targets_file=apk_path,
        started_at=started_at,
        finished_at=finished_at,
        domain="android",
        tools={
            spec.name: {
                "image": spec.image,
                "version": table.versions.get(spec.name, "unknown"),
            }
            for spec in TOOL_REGISTRY.values()
        },
        errors=tool_errors,
    )

    generate_report(base)