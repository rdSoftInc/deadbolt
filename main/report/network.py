"""Report model for normalized network assessment evidence."""

from collections import Counter
import json
from pathlib import Path

from main.report.generator import SEVERITY_ORDER, _relative_evidence


def build_network_report_model(run_dir: Path, meta: dict, state: dict) -> dict:
    inventory = json.loads((run_dir / "normalized" / "network-inventory.json").read_text(encoding="utf-8"))
    quality_path = run_dir / "normalized" / "network-quality.json"
    quality = json.loads(quality_path.read_text(encoding="utf-8")) if quality_path.is_file() else {
        "grade": "unknown", "warnings": ["Network quality artifact is missing."], "metrics": {}
    }
    records = json.loads((run_dir / "normalized" / "findings.json").read_text(encoding="utf-8"))
    findings = [item for item in records if item.get("kind") == "finding"]
    for item in findings:
        item["severity"] = (item.get("severity") or "info").lower()
        item["verification_status"] = item.get("metadata", {}).get("verification_status", "Unverified")
        item["evidence"] = _relative_evidence(item.get("evidence_path"), run_dir)
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item.get("title", "")))
    phases = []
    nmap = state.get("tools", {}).get("nmap", {})
    for name, item in nmap.get("phases", {}).items():
        phases.append({
            "name": name,
            "status": item.get("status", "unknown"),
            "duration": item.get("duration_seconds"),
            "returncode": item.get("returncode"),
            "output": item.get("output_file", "—"),
            "log": item.get("log_file", "—"),
        })
    hosts = inventory.get("hosts", [])
    services = inventory.get("services", [])
    os_observations = inventory.get("os_observations", [])
    scripts = inventory.get("scripts", [])
    review = inventory.get("exposure_review", [])
    summary = inventory.get("summary", {})
    coverage = [
        {"label": "Targets submitted", "value": state.get("targets", {}).get("entries", 0), "items": []},
        {"label": "Hosts observed", "value": len(hosts), "items": [item["primary_address"] for item in hosts]},
        {"label": "Open services", "value": len(services), "items": [f"{item['host']} — {item['port']}/{item['protocol']} — {item.get('service') or 'unknown'}" for item in services]},
        {"label": "Services identified", "value": summary.get("identified_services", 0), "items": []},
        {"label": "OS candidates", "value": len(os_observations), "items": [f"{item['host']} — {item.get('name') or 'unknown'} — {item.get('accuracy', 0)}%" for item in os_observations]},
        {"label": "Vulnerability signals", "value": len(findings), "items": [f"{item['severity'].upper()} — {item['title']} — {item['asset']}" for item in findings]},
    ]
    mode = str(meta.get("scan_profile", "standard"))
    limitations = [
        "Open services are inventory observations, not vulnerabilities by themselves.",
        "Service and OS identification are probabilistic and require analyst validation.",
        "Only ports authorized by the engagement and selected profile were assessed.",
        "No NSE vulnerability scripts were enabled in this assessment stage.",
    ]
    limitations.extend(quality.get("warnings", []))
    if mode == "safe":
        limitations.append("Safe mode omits UDP, OS detection, version probing, and vulnerability scripts.")
    elif mode == "standard":
        limitations.append("Standard mode omits UDP, OS detection, full-port coverage, and vulnerability scripts.")
    if any(item.get("state") == "open|filtered" for item in services):
        limitations.append("UDP open|filtered results cannot distinguish an open service from packet filtering.")
    limitations.append("A lack of automated findings does not establish that the environment is vulnerability-free.")
    severity_counts = Counter(item["severity"] for item in findings)
    highest = max(
        (item["severity"] for item in findings),
        key=lambda value: SEVERITY_ORDER.get(value, 0),
        default="none",
    )
    engagement = state.get("engagement", {})
    return {
        "meta": meta,
        "domain": "network",
        "assessment_profile": mode.replace("-", " ").title(),
        "targets_display": _relative_evidence(meta.get("targets_file"), run_dir),
        "scope_snapshot": engagement.get("snapshot", "Not recorded"),
        "scope_hash": engagement.get("hash", "Not recorded"),
        "inventory": inventory,
        "quality": quality,
        "summary": summary,
        "hosts": hosts,
        "services": services,
        "os_observations": os_observations,
        "scripts": scripts,
        "exposure_review": review,
        "findings": findings,
        "phases": phases,
        "coverage": coverage,
        "limitations": limitations,
        "severity_counts": dict(severity_counts),
        "highest_severity": highest,
    }
