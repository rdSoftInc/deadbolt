"""Post-scan scope and evidence-quality checks for network runs."""

from __future__ import annotations

import json
from pathlib import Path


class NetworkQualityError(ValueError):
    """Raised when collected evidence violates the authorized scan plan."""


def evaluate_network_quality(run_dir: Path, inventory: dict, state: dict) -> dict:
    nmap = state.get("tools", {}).get("nmap", {})
    plan = nmap.get("plan", {})
    effective = set(plan.get("effective_ports") or [])
    excluded = set(plan.get("excluded_ports") or [])
    services = inventory.get("services", [])
    violations = []
    for item in services:
        port = int(item.get("port", 0))
        if effective and port not in effective:
            violations.append(f"{item.get('host')}:{port}/{item.get('protocol')} was outside allowed ports")
        if port in excluded:
            violations.append(f"{item.get('host')}:{port}/{item.get('protocol')} was explicitly denied")
    if violations:
        raise NetworkQualityError("Post-scan port-scope verification failed:\n" + "\n".join(violations))

    summary = inventory.get("summary", {})
    scans = inventory.get("scans", [])
    mode = state.get("run", {}).get("mode", "standard")
    warnings = []
    unsuccessful = [item.get("source", "unknown") for item in scans if item.get("exit") not in {None, "success"}]
    if unsuccessful:
        warnings.append(f"{len(unsuccessful)} XML artifact(s) did not record a successful Nmap exit.")
    if not summary.get("hosts_observed"):
        warnings.append("No hosts were observed; routing, filtering, target availability, and authorization should be reviewed.")
    if mode != "safe" and summary.get("open_services") and not summary.get("identified_services"):
        warnings.append("Open ports were observed but none had an identified service.")
    if mode == "deep" and summary.get("hosts_up") and not summary.get("os_candidates"):
        warnings.append("Deep mode returned no OS candidates; OS evidence is incomplete.")
    complete_phases = sum(
        item.get("status") == "complete" for item in nmap.get("phases", {}).values()
    )
    if len(scans) != complete_phases:
        warnings.append(
            f"Parsed XML artifact count ({len(scans)}) differs from completed phase count ({complete_phases})."
        )
    identified = int(summary.get("identified_services", 0))
    open_services = int(summary.get("open_services", 0))
    product_versions = sum(bool(item.get("product") or item.get("version")) for item in services)
    grade = "limited" if not summary.get("hosts_observed") or unsuccessful else "partial" if warnings else "complete"
    quality = {
        "schema": 1,
        "grade": grade,
        "scope_verified": True,
        "warnings": warnings,
        "metrics": {
            "xml_artifacts": len(scans),
            "completed_phases": complete_phases,
            "hosts_observed": int(summary.get("hosts_observed", 0)),
            "hosts_up": int(summary.get("hosts_up", 0)),
            "open_services": open_services,
            "service_identification_ratio": round(identified / open_services, 3) if open_services else None,
            "product_version_ratio": round(product_versions / open_services, 3) if open_services else None,
            "os_candidates": int(summary.get("os_candidates", 0)),
            "script_observations": int(summary.get("script_observations", 0)),
        },
    }
    destination = run_dir / "normalized" / "network-quality.json"
    destination.write_text(json.dumps(quality, indent=2) + "\n", encoding="utf-8")
    return quality
