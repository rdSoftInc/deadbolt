import json
import threading
from typing import Optional, Dict, List
from datetime import datetime, timezone
from pathlib import Path

from main.core.execution_table import ExecutionTable
from main.core.metadata import write_metadata
from main.core.scope import validate_targets
from main.core.tool_registry import TOOL_REGISTRY, ToolSpec
from main.execution.latest_version import get_latest_version
from main.execution.version import get_tool_version
from main.execution.version_cache import get_cached_versions
from main.schema.normalize import Finding
from main.report.generator import generate_report
from main.tools.runtime_registry import TOOL_RUNTIMES

from main.utils.resume import _resolve_run_base
from main.utils.state import hash_file, load_state, save_state
from main.utils.targets import _extract_domains_from_targets
from main.utils.worklists import (
    _findings_to_work_items,
    _write_or_merge_worklist_txt,
)

PHASE_ORDER = ["discovery", "enumeration", "vulnerability"]

# Ensures we run producers before consumers within a phase
CONSUME_RANK = {"targets": 0, "assets": 1, "paths": 2, "findings": 3}

# ---------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------

def run_tool(
    *,
    spec: ToolSpec,
    table: ExecutionTable,
    input_file: Path,
    base_dir: Path,
) -> List[Finding]:
    table.tool_started(spec.name)

    runtime = TOOL_RUNTIMES.get(spec.name)
    if not runtime:
        raise RuntimeError(f"No runtime registered for {spec.name}")

    raw_name = runtime.raw_subdir or spec.name
    raw_dir = base_dir / "raw" / raw_name
    raw_dir.mkdir(parents=True, exist_ok=True)

    output = raw_dir / runtime.output_name

    runtime.runner(input_file, output)
    findings = runtime.parser(output)

    if runtime.postprocess:
        runtime.postprocess(findings)

    return findings


# ---------------------------------------------------------------------
# Main scan runner
# ---------------------------------------------------------------------

def run_scan(targets_path: str, resume_from: Optional[Path] = None) -> None:
    targets_file = Path(targets_path)

    # Hard scope gate
    validate_targets(
        targets_file=targets_file,
        scope_file=Path("scope.yaml"),
    )

    started_at = datetime.now(timezone.utc)

    if resume_from is not None:
        resume_from = resume_from.resolve()

        if not resume_from.is_dir():
            raise RuntimeError("--resume-from must be an existing run directory")

        required = ["state.json", "work"]
        for name in required:
            if not (resume_from / name).exists():
                raise RuntimeError(
                    f"Invalid run directory (missing {name}): {resume_from}"
                )

    base = _resolve_run_base(resume_from)
    base.mkdir(parents=True, exist_ok=True)
    run_id = base.name

    # Load persistent state
    state_file = base / "state.json"
    state = load_state(state_file)
    state.setdefault("schema", 1)
    state.setdefault("tools", {})

    norm_dir = base / "normalized"
    work_dir = base / "work"
    norm_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    # Discovery targets
    domains = _extract_domains_from_targets(targets_file)
    discovery_targets = work_dir / "targets_domains.txt"
    _write_or_merge_worklist_txt(discovery_targets, domains)

    # Execution table
    table = ExecutionTable()
    for tool in TOOL_REGISTRY.values():
        table.register_tool(tool.name, "detecting…")
    table.start()

    # Async version detection (display only)
    def resolve_versions():
        for spec in TOOL_REGISTRY.values():

            def detect(tool: ToolSpec = spec):
                installed, latest = get_cached_versions(
                    image=tool.image,
                    resolve_installed=get_tool_version,
                    resolve_latest=get_latest_version,
                )

                table.versions[tool.name] = installed
                table.latest_versions[tool.name] = latest

                if latest is None:
                    table.update_status[tool.name] = "-"
                elif installed == latest:
                    table.update_status[tool.name] = "latest"
                else:
                    table.update_status[tool.name] = latest

                table._refresh()

            threading.Thread(target=detect, daemon=True).start()

    threading.Thread(target=resolve_versions, daemon=True).start()

    # Artifact registry (ownership enforced)
    artifacts: Dict[str, Path | None] = {
        "targets": discovery_targets,
        "assets": None,
        "paths": None,
        "findings": None,
    }

    # Resume artifact seeding (directory-only)
    if resume_from:
        resume_work_dir = resume_from / "work"

        candidates = {
            "targets": [
                resume_work_dir / "targets_domains.txt",
            ],
            "assets": [
                resume_work_dir / "enumeration.assets.txt",
                resume_work_dir / "discovery.assets.txt",
            ],
            "paths": [
                resume_work_dir / "enumeration.paths.txt",
            ],
        }

        found_any = False

        for artifact, paths in candidates.items():
            for p in paths:
                if p.exists():
                    artifacts[artifact] = p
                    found_any = True
                    break

        if not found_any:
            raise RuntimeError(
                "Resume directory contains no usable work artifacts"
            )

    all_findings: List[Finding] = []
    tool_errors: Dict[str, str] = {}

    try:
        for phase in PHASE_ORDER:
            phase_tools = [t for t in TOOL_REGISTRY.values() if t.phase == phase]
            phase_tools.sort(key=lambda t: CONSUME_RANK[t.consumes])

            # --------------------------------------------------
            # Phase boundary artifact seeding
            # --------------------------------------------------

            if phase == "enumeration":
                assets = work_dir / "discovery.assets.txt"

                if assets.exists() and assets.stat().st_size > 0:
                    artifacts["assets"] = assets
                else:
                    # Fallback: treat original targets as assets
                    fallback = work_dir / "enumeration.assets.fallback.txt"
                    _write_or_merge_worklist_txt(
                        fallback,
                        _extract_domains_from_targets(targets_file),
                    )
                    artifacts["assets"] = fallback

            if phase == "vulnerability" and artifacts["assets"] is None:
                prev = work_dir / "enumeration.assets.txt"
                if prev.exists():
                    artifacts["assets"] = prev
            
            if phase == "vulnerability" and artifacts["paths"] is None:
                prev = work_dir / "enumeration.paths.txt"
                if prev.exists():
                    artifacts["paths"] = prev

            for tool in phase_tools:

                input_file = artifacts.get(tool.consumes)
                if input_file is None or not input_file.exists() or input_file.stat().st_size == 0:
                    table.tool_skipped(tool.name)
                    continue

                input_hash = hash_file(input_file)
                tool_state = state["tools"].get(tool.name)

                # Hash-based skip
                if (
                    tool_state
                    and tool_state.get("status") == "done"
                    and tool_state.get("input_hash") == input_hash
                ):
                    table.tool_skipped(tool.name)

                    out_rel = tool_state.get("output_file")
                    if out_rel:
                        out_path = base / out_rel
                        if out_path.exists():
                            artifacts[tool.produces] = out_path
                    continue

                tool_started_at = datetime.now(timezone.utc)

                try:
                    findings = run_tool(
                        spec=tool,
                        table=table,
                        input_file=input_file,
                        base_dir=base,
                    )
                except Exception as e:
                    table.tool_failed(tool.name)
                    tool_errors[tool.name] = str(e)

                    state["tools"][tool.name] = {
                        "status": "failed",
                        "version": table.versions.get(tool.name),
                        "input_type": tool.consumes,
                        "input_hash": input_hash,
                        "started_at": tool_started_at.isoformat(),
                        "finished_at": datetime.now(timezone.utc).isoformat(),
                    }
                    save_state(state_file, state)
                    continue

                table.tool_finished(tool.name, len(findings))

                # Normalized snapshot
                out_json = norm_dir / f"{tool.name}.{tool.produces}.json"
                out_json.write_text(
                    json.dumps([f.model_dump() for f in findings], indent=2, default=str),
                    encoding="utf-8",
                )

                # Phase-scoped artifact naming
                if tool.name == "httpx_paths":
                    artifact_name = f"{phase}.{tool.produces}.enriched.txt"
                else:
                    artifact_name = f"{phase}.{tool.produces}.txt"

                out_txt = work_dir / artifact_name

                items = _findings_to_work_items(tool.produces, findings)

                # Always materialize artifact, even if empty
                if not out_txt.exists():
                    out_txt.write_text("", encoding="utf-8")

                if items:
                    _write_or_merge_worklist_txt(out_txt, items)

                # Phase owns its artifact explicitly
                artifacts[tool.produces] = out_txt

                # Persist state
                state["tools"][tool.name] = {
                    "status": "done",
                    "version": table.versions.get(tool.name),
                    "input_type": tool.consumes,
                    "input_hash": input_hash,
                    "output_type": tool.produces,
                    "output_file": str(out_txt.relative_to(base)),
                    "started_at": tool_started_at.isoformat(),
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                }
                save_state(state_file, state)

                if tool.produces == "findings":
                    all_findings.extend(findings)

    finally:
        table.stop()

    finished_at = datetime.now(timezone.utc)

    # Final findings
    (norm_dir / "findings.json").write_text(
        json.dumps([f.model_dump() for f in all_findings], indent=2, default=str),
        encoding="utf-8",
    )

    # Metadata + report
    write_metadata(
        base_dir=base,
        run_id=run_id,
        targets_file=targets_file,
        started_at=started_at,
        finished_at=finished_at,
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