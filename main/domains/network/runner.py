"""Run an auditable, scope-bound, resumable network assessment."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_network
import json
from pathlib import Path
import shutil
from typing import Callable

from main.core.engagement import load_engagement
from main.core.tool_manifest import get_tool_config
from main.domains.network.nmap_policy import NmapPlan, build_nmap_plan
from main.domains.network.nmap_executor import (
    NetworkExecutionCancelled,
    PhaseExecution,
    execute_nmap_phase,
)
from main.domains.network.nmap_parser import NmapParseError, normalize_nmap_outputs
from main.domains.network.quality import NetworkQualityError, evaluate_network_quality
from main.report.generator import generate_report
from main.version import get_version
from main.domains.network.profiles import NetworkScanMode, normalize_network_mode
from main.domains.network.targets import enforce_network_scope, parse_network_targets
from main.utils.resume import _resolve_run_base
from main.utils.state import hash_file


@dataclass(frozen=True)
class NetworkRunSummary:
    run_dir: Path
    run_id: str
    targets: int
    address_count: int
    mode: NetworkScanMode
    resumed: bool
    status: str = "initialized"
    completed_phases: int = 0
    cached_phases: int = 0


def _save_json(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _phase_output(phase) -> Path:
    arguments = phase.arguments
    return Path(arguments[arguments.index("-oX") + 1].removeprefix("/deadbolt/"))


def _completed_record_valid(base: Path, record: dict) -> bool:
    relative = record.get("output_file")
    digest = record.get("output_sha256")
    if record.get("status") != "complete" or not relative or not digest:
        return False
    output = base / relative
    return output.is_file() and hash_file(output) == digest


def run_network(
    targets_path: str | Path,
    engagement_path: str | Path,
    *,
    mode: NetworkScanMode | str | None = None,
    resume_from: Path | None = None,
    execute: bool = True,
    phase_executor: Callable[..., PhaseExecution] | None = None,
    progress: Callable[[str, str], None] | None = None,
) -> NetworkRunSummary:
    """Validate authorization, persist the plan, and execute unfinished phases."""

    targets_file = Path(targets_path).resolve()
    engagement_file = Path(engagement_path).resolve()
    engagement = load_engagement(engagement_file)
    selected_mode = normalize_network_mode(mode or engagement.mode)
    targets = parse_network_targets(targets_file)
    enforce_network_scope(targets, engagement)
    nmap = get_tool_config("nmap")

    base = _resolve_run_base(resume_from)
    resumed = resume_from is not None
    base.mkdir(parents=True, exist_ok=True)
    work = base / "work"
    scope_dir = base / "scope"
    work.mkdir(exist_ok=True)
    scope_dir.mkdir(exist_ok=True)

    input_snapshot = work / "input.network-targets.txt"
    canonical = "".join(f"{value}\n" for value in targets.values)
    engagement_bytes = engagement_file.read_bytes()
    engagement_hash = hashlib.sha256(engagement_bytes).hexdigest()
    engagement_snapshot = scope_dir / f"engagement-{engagement_hash}.yaml"

    if resumed:
        state_path = base / "state.json"
        if not state_path.is_file():
            raise RuntimeError("network resume directory has no state.json")
        prior_state = json.loads(state_path.read_text(encoding="utf-8"))
        if prior_state.get("domain") != "network":
            raise RuntimeError("resume directory is not a network assessment")
        if input_snapshot.is_file() and input_snapshot.read_text(encoding="utf-8") != canonical:
            raise RuntimeError("network resume targets differ from the original canonical targets")
        if prior_state.get("engagement", {}).get("hash") != engagement_hash:
            raise RuntimeError("network resume engagement differs from the original authorization snapshot")
        recorded_mode = prior_state.get("run", {}).get("mode")
        if recorded_mode:
            selected_mode = normalize_network_mode(recorded_mode)

    input_snapshot.write_text(canonical, encoding="utf-8")
    ipv4_values: list[str] = []
    ipv6_values: list[str] = []
    for value in targets.values:
        try:
            network = ip_network(value, strict=False)
        except ValueError:
            # Avoid duplicate traffic and false failures for names without an
            # AAAA record. Explicit IPv6 literals/CIDRs select the IPv6 phase.
            ipv4_values.append(value)
        else:
            (ipv4_values if network.version == 4 else ipv6_values).append(value)
    family_plans = []
    for family, values in ((4, ipv4_values), (6, ipv6_values)):
        if not values:
            continue
        family_file = work / f"input.network-targets-ipv{family}.txt"
        family_file.write_text("".join(f"{value}\n" for value in values), encoding="utf-8")
        family_plans.append(build_nmap_plan(
            engagement,
            selected_mode,
            image=nmap.versioned_image,
            input_path=f"/deadbolt/work/{family_file.name}",
            address_family=family,
            phase_suffix="_ipv6" if family == 6 else "",
        ))
    first_plan = family_plans[0]
    scan_plan = NmapPlan(
        mode=selected_mode,
        image=nmap.versioned_image,
        input_paths=tuple(path for plan in family_plans for path in plan.input_paths),
        phases=tuple(phase for plan in family_plans for phase in plan.phases),
        effective_ports=first_plan.effective_ports,
        excluded_ports=first_plan.excluded_ports,
        max_rate=first_plan.max_rate,
        nse_scripts=first_plan.nse_scripts,
    )
    plan_path = work / "nmap-plan.json"
    plan_document = json.dumps(scan_plan.to_dict(), indent=2) + "\n"
    if resumed and plan_path.is_file() and plan_path.read_text(encoding="utf-8") != plan_document:
        raise RuntimeError(
            "network resume Nmap policy differs from the original plan; start a new run"
        )
    plan_path.write_text(plan_document, encoding="utf-8")

    if not engagement_snapshot.exists():
        shutil.copyfile(engagement_file, engagement_snapshot)
        engagement_snapshot.chmod(0o600)

    now = datetime.now(timezone.utc).isoformat()
    prior_phases = (
        prior_state.get("tools", {}).get("nmap", {}).get("phases", {}) if resumed else {}
    )
    state = {
        "schema": 1,
        "domain": "network",
        "status": "initialized",
        "run": {"mode": selected_mode.value, "awaiting_scanners": True},
        "targets": {
            "file": "work/input.network-targets.txt",
            "sha256": hash_file(input_snapshot),
            "entries": len(targets.values),
            "address_count": targets.address_count,
        },
        "engagement": {
            "name": engagement.name,
            "hash": engagement_hash,
            "snapshot": str(engagement_snapshot.relative_to(base)),
        },
        "tools": {
            "nmap": {
                "version": nmap.display_version,
                "status": "planned",
                "plan_file": "work/nmap-plan.json",
                "plan_sha256": hash_file(plan_path),
                "plan": scan_plan.to_dict(),
                "phases": prior_phases,
            }
        },
    }
    state_path = base / "state.json"
    _save_json(state_path, state)
    previous_meta = {}
    if resumed and (base / "meta.json").is_file():
        previous_meta = json.loads((base / "meta.json").read_text(encoding="utf-8"))
    meta = {
        "run_id": base.name,
        "domain": "network",
        "status": "initialized",
        "initialized_at": previous_meta.get("initialized_at", now),
        "finished_at": None,
        "targets_file": str(targets_file),
        "engagement": engagement.redacted_summary(),
        "scan_profile": selected_mode.value,
        "deadbolt_version": get_version(),
        "scope_snapshot": str(engagement_snapshot.relative_to(base)),
        "scope_hash": engagement_hash,
        "tools": {"nmap": {"image": nmap.versioned_image, "version": nmap.display_version}},
        "errors": {},
        "message": "Network workflow initialized with a scope-bound Nmap plan; no scanner was executed.",
    }
    meta_path = base / "meta.json"
    _save_json(meta_path, meta)
    if not execute:
        return NetworkRunSummary(
            base, base.name, len(targets.values), targets.address_count, selected_mode, resumed
        )

    executor = phase_executor or execute_nmap_phase
    completed = cached = 0
    state["status"] = "running"
    state["run"]["awaiting_scanners"] = False
    state["tools"]["nmap"]["status"] = "running"
    _save_json(state_path, state)
    meta["status"] = "running"
    meta["started_at"] = previous_meta.get("started_at", now)
    meta["message"] = "Nmap collection is running."
    _save_json(meta_path, meta)
    try:
        for phase in scan_plan.phases:
            existing = prior_phases.get(phase.name, {})
            if resumed and _completed_record_valid(base, existing):
                cached += 1
                completed += 1
                if progress:
                    progress(phase.name, "cached")
                continue
            started_at = datetime.now(timezone.utc).isoformat()
            record = {
                "status": "running",
                "started_at": started_at,
                "finished_at": None,
                "duration_seconds": None,
                "returncode": None,
            }
            state["tools"]["nmap"]["phases"][phase.name] = record
            _save_json(state_path, state)
            if progress:
                progress(phase.name, "started")
            output_relative = _phase_output(phase)
            output = base / output_relative
            # A retry must prove it produced fresh XML; never accept an output
            # left behind by a failed or interrupted attempt.
            output.unlink(missing_ok=True)
            try:
                result = executor(
                    scan_plan,
                    phase,
                    base,
                    on_output=(lambda line, name=phase.name: progress(name, line)) if progress else None,
                )
            except NetworkExecutionCancelled:
                raise
            except Exception as exc:
                internal_log = base / "logs" / f"nmap-{phase.name}.log"
                internal_log.parent.mkdir(exist_ok=True)
                internal_log.write_text(f"Deadbolt executor error: {exc}\n", encoding="utf-8")
                result = PhaseExecution(125, 0.0, internal_log)
            succeeded = result.returncode == 0 and output.is_file()
            record.update({
                "status": "complete" if succeeded else "failed",
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(result.duration_seconds, 3),
                "returncode": result.returncode,
                "timed_out": result.timed_out,
                "log_file": str(result.log_path.relative_to(base)),
                "output_file": str(output_relative),
                "output_sha256": hash_file(output) if output.is_file() else None,
            })
            _save_json(state_path, state)
            if not succeeded:
                state["status"] = "failed"
                state["tools"]["nmap"]["status"] = "failed"
                meta["status"] = "failed"
                meta["finished_at"] = datetime.now(timezone.utc).isoformat()
                meta["message"] = f"Nmap phase {phase.name} failed; inspect {record['log_file']}."
                _save_json(state_path, state)
                _save_json(meta_path, meta)
                if progress:
                    progress(phase.name, "failed")
                return NetworkRunSummary(
                    base, base.name, len(targets.values), targets.address_count,
                    selected_mode, resumed, "failed", completed, cached,
                )
            completed += 1
            if progress:
                progress(phase.name, "complete")
    except NetworkExecutionCancelled:
        active = state["tools"]["nmap"]["phases"].get(phase.name, {})
        active.update({
            "status": "interrupted",
            "finished_at": datetime.now(timezone.utc).isoformat(),
        })
        state["status"] = "interrupted"
        state["tools"]["nmap"]["status"] = "interrupted"
        meta["status"] = "interrupted"
        meta["finished_at"] = datetime.now(timezone.utc).isoformat()
        meta["message"] = "Network assessment was interrupted and can be resumed."
        _save_json(state_path, state)
        _save_json(meta_path, meta)
        raise

    xml_paths = [
        base / item["output_file"]
        for item in state["tools"]["nmap"]["phases"].values()
        if item.get("status") == "complete" and item.get("output_file")
    ]
    try:
        inventory = normalize_nmap_outputs(base, xml_paths)
        quality = evaluate_network_quality(base, inventory, state)
        inventory_path = base / "normalized" / "network-inventory.json"
        findings_path = base / "normalized" / "findings.json"
        quality_path = base / "normalized" / "network-quality.json"
        state["tools"]["nmap"]["normalized"] = {
            "inventory": "normalized/network-inventory.json",
            "inventory_sha256": hash_file(inventory_path),
            "findings": "normalized/findings.json",
            "findings_sha256": hash_file(findings_path),
            "quality": "normalized/network-quality.json",
            "quality_sha256": hash_file(quality_path),
        }
        state["status"] = "complete"
        state["tools"]["nmap"]["status"] = "complete"
        meta["status"] = "complete"
        meta["finished_at"] = datetime.now(timezone.utc).isoformat()
        meta["message"] = "Network collection, normalization, and reporting completed."
        meta["network_summary"] = inventory["summary"]
        meta["network_quality"] = {"grade": quality["grade"], "warnings": len(quality["warnings"])}
        _save_json(state_path, state)
        _save_json(meta_path, meta)
        generate_report(base)
    except (NmapParseError, NetworkQualityError, OSError, ValueError, json.JSONDecodeError) as exc:
        state["status"] = "processing_failed"
        state["tools"]["nmap"]["status"] = "processing_failed"
        meta["status"] = "processing_failed"
        meta["finished_at"] = datetime.now(timezone.utc).isoformat()
        meta["errors"]["network_processing"] = str(exc)
        meta["message"] = "Nmap XML processing or report generation failed; raw evidence is preserved."
        _save_json(state_path, state)
        _save_json(meta_path, meta)
        return NetworkRunSummary(
            base, base.name, len(targets.values), targets.address_count,
            selected_mode, resumed, "processing_failed", completed, cached,
        )
    return NetworkRunSummary(
        base, base.name, len(targets.values), targets.address_count,
        selected_mode, resumed, "complete", completed, cached,
    )
