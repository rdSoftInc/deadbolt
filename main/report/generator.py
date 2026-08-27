"""Generate portable technical and stakeholder reports from one run model."""

from collections import Counter
from datetime import datetime
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from main.core.execution_table import format_duration
from main.core.severity import severity_at_least
from main.schema.api_evidence import load_api_inventory
from main.utils.url_hygiene import (
    is_non_api_namespace,
    is_parser_artifact,
    is_recursive_path_artifact,
    safe_url,
    surface_type,
)


DEFAULT_MIN_SEVERITY = "medium"
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def load_tool_registry(domain: str):
    if domain == "web":
        from main.domains.web.tool_registry import TOOL_REGISTRY
        return TOOL_REGISTRY
    if domain == "android":
        from main.domains.android.tool_registry import TOOL_REGISTRY
        return TOOL_REGISTRY
    if domain == "ios":
        from main.domains.ios.tool_registry import TOOL_REGISTRY
        return TOOL_REGISTRY
    return {}


def _lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _api_inventory_entries(path: Path) -> list[dict[str, Any]]:
    """Read both canonical and pre-schema API inventory artifacts."""

    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        inventory = load_api_inventory(payload)
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        return []
    entries = [entry.model_dump(mode="json", exclude_none=True) for entry in inventory.entries]
    entries = [
        item for item in entries
        if not is_non_api_namespace(str(item.get("url", "")))
        and not is_parser_artifact(str(item.get("url", "")))
        and surface_type(str(item.get("url", ""))) != "static resource"
    ]
    for item in entries:
        expressions = [item.get("raw_expression")]
        expressions.extend(
            provenance.get("raw_expression")
            for provenance in item.get("provenance", [])
            if isinstance(provenance, dict)
        )
        item["raw_expressions"] = list(dict.fromkeys(
            str(expression) for expression in expressions if expression
        ))
    return entries


def _relative_evidence(value: str | None, run_dir: Path) -> str:
    if not value:
        return "—"
    path = Path(value)
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except (OSError, ValueError):
        return path.name if path.is_absolute() else str(path)


def _display_target(value: str, mapping: dict[str, str]) -> str:
    """Map Docker transport URLs back to their human-facing local target."""
    for transport, canonical in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        transport_root = transport.rstrip("/")
        canonical_root = canonical.rstrip("/")
        if value in {transport, transport_root}:
            return safe_url(canonical)
        if value.startswith(transport_root + "/"):
            return safe_url(canonical_root + value[len(transport_root):])
    return safe_url(value)


def _duration(started: str | None, finished: str | None) -> str:
    if not started or not finished:
        return "—"
    try:
        seconds = (datetime.fromisoformat(finished) - datetime.fromisoformat(started)).total_seconds()
        return format_duration(seconds)
    except (TypeError, ValueError):
        return "—"


def _nuclei_tool_severities(run_dir: Path) -> dict[str, str]:
    """Recover scanner-native severities for legacy normalized records."""
    result = {}
    raw = run_dir / "raw" / "nuclei" / "nuclei.jsonl"
    for line in _lines(raw):
        try:
            record = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        template_id = record.get("template-id")
        severity = record.get("info", {}).get("severity")
        if template_id and severity:
            result[str(template_id)] = str(severity).lower()
    return result


def _deduplicate_surface(records: list[dict[str, Any]], rejected: set[str], run_dir: Path, mapping: dict[str, str]):
    unique: dict[str, dict[str, Any]] = {}
    for record in records:
        item = dict(record)
        item["asset"] = _display_target(str(item.get("asset", "")), mapping)
        key = str(item.get("asset", ""))
        if not key or is_parser_artifact(key):
            continue
        item["surface_type"] = surface_type(key)
        if key not in unique:
            item["sources"] = [item.get("tool", "unknown")]
            item["kinds"] = [item.get("kind", "asset")]
            item["in_scope"] = key.rstrip("/") not in rejected
            item["evidence"] = _relative_evidence(item.get("evidence_path"), run_dir)
            unique[key] = item
        else:
            source = item.get("tool", "unknown")
            if source not in unique[key]["sources"]:
                unique[key]["sources"].append(source)
            kind = item.get("kind", "asset")
            if kind not in unique[key]["kinds"]:
                unique[key]["kinds"].append(kind)
                unique[key]["kind"] = ", ".join(unique[key]["kinds"])
    return list(unique.values())


def _coverage(run_dir: Path, domain: str, surface: list[dict[str, Any]], findings: list[dict[str, Any]], mapping: dict[str, str]):
    if domain != "web":
        return [
            {"label": "Surface records", "value": len(surface), "items": [item.get("asset", "") for item in surface]},
            {"label": "Reportable findings", "value": len(findings), "items": [f"{item.get('severity', 'info').upper()} — {item.get('title', 'Finding')} — {item.get('asset', '')}" for item in findings]},
        ]
    work = run_dir / "work"
    if (work / "targets.transport.txt").is_file():
        stages = [
            ("Input targets", work / "input.targets.txt"),
            ("Live web assets", work / "discovery.live.in_scope.txt"),
            ("Crawler URLs discovered", work / "enumeration.paths.in_scope.txt"),
            ("Responsive URLs", work / "enumeration.live-paths.in_scope.txt"),
            ("Confirmed application routes", work / "enumeration.application-routes.in_scope.txt"),
            ("Unconfirmed SPA routes", work / "enumeration.routes.candidates.txt"),
            ("Vulnerability matches", run_dir / "normalized" / "nuclei.findings.json"),
        ]
    else:
        stages = [
            ("Input targets", work / "input.targets.txt"),
            ("Subdomains discovered", work / "discovery.subfinder.domains.txt"),
            ("DNS-resolved assets", work / "discovery.dnsx.resolved.txt"),
            ("Assets in scope", work / "discovery.resolved.in_scope.txt"),
            ("Live web assets", work / "discovery.live.in_scope.txt"),
            ("Crawler URLs discovered", work / "enumeration.paths.in_scope.txt"),
            ("Responsive URLs", work / "enumeration.live-paths.in_scope.txt"),
            ("Confirmed application routes", work / "enumeration.application-routes.in_scope.txt"),
            ("Unconfirmed SPA routes", work / "enumeration.routes.candidates.txt"),
            ("Vulnerability matches", run_dir / "normalized" / "nuclei.findings.json"),
        ]
    api_inventory_path = work / "enumeration.api-inventory.json"
    if _api_inventory_entries(api_inventory_path):
        stages.insert(-1, ("API operations understood", api_inventory_path))
    result = []
    for label, path in stages:
        if path.suffix == ".json" and path.is_file():
            try:
                value = len(
                    _api_inventory_entries(path)
                    if path == api_inventory_path
                    else json.loads(path.read_text(encoding="utf-8"))
                )
            except (OSError, ValueError, json.JSONDecodeError):
                value = 0
        else:
            value = len(set(_lines(path)))
        if path.suffix == ".json" and path.is_file():
            try:
                payload = (
                    _api_inventory_entries(path)
                    if path == api_inventory_path
                    else json.loads(path.read_text(encoding="utf-8"))
                )
                if path == api_inventory_path:
                    items = sorted({
                        f"{item.get('method') or 'UNKNOWN'} — "
                        f"{safe_url(_display_target(str(item.get('url', '')), mapping), canonical=True)} — "
                        f"{item.get('evidence_status', 'discovered')} / {item.get('confidence', 'low')}"
                        for item in payload
                    })
                else:
                    items = [f"{item.get('severity', 'info').upper()} — {item.get('title', 'Finding')} — {_display_target(str(item.get('asset', '')), mapping)}" for item in payload]
            except (OSError, ValueError, json.JSONDecodeError, TypeError):
                items = []
        else:
            items = sorted({
                displayed for item in _lines(path)
                if not is_parser_artifact(displayed := _display_target(item, mapping))
            })
            if label == "Confirmed application routes":
                items = [item for item in items if surface_type(item) != "static resource"]
            value = len(items)
        if path.suffix == ".json":
            value = len(items)
        result.append({"label": label, "value": value, "items": items})
    return result


def build_report_model(run_dir: Path) -> dict[str, Any]:
    """Build the single authoritative model consumed by both report views."""
    meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    all_records = json.loads(
        (run_dir / "normalized" / "findings.json").read_text(encoding="utf-8")
    )
    domain = meta.get("domain", "web")
    if domain == "network":
        state_path = run_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.is_file() else {}
        from main.report.network import build_network_report_model
        return build_network_report_model(run_dir, meta, state)
    registry = load_tool_registry(domain)
    target_mapping = meta.get("target_mapping") or {}
    rejected = {
        _display_target(item, target_mapping).rstrip("/")
        for item in _lines(run_dir / "work" / "scope.rejected.txt")
    }
    nuclei_severities = _nuclei_tool_severities(run_dir)

    surface_records = [record for record in all_records if record.get("kind") != "finding"]
    surface = _deduplicate_surface(surface_records, rejected, run_dir, target_mapping)
    in_scope_surface = [item for item in surface if item["in_scope"]]
    excluded_surface = [item for item in surface if not item["in_scope"]]

    findings = []
    for record in all_records:
        if record.get("kind") != "finding":
            continue
        spec = registry.get(record.get("tool"))
        severity = (record.get("severity") or "info").lower()
        if spec and spec.severity_gated and not severity_at_least(severity, DEFAULT_MIN_SEVERITY):
            continue
        item = dict(record)
        item["asset"] = _display_target(str(item.get("asset", "")), target_mapping)
        item["severity"] = severity
        item["verification_status"] = item.get("metadata", {}).get(
            "verification_status", "Unverified"
        )
        item["tool_severity"] = item.get("metadata", {}).get("tool_severity") or nuclei_severities.get(
            str(item.get("template_id", "")), severity
        )
        item["evidence"] = _relative_evidence(item.get("evidence_path"), run_dir)
        findings.append(item)
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item.get("title", "")))

    state_path = run_dir / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.is_file() else {"tools": {}}
    executions = []
    for name, info in state.get("tools", {}).items():
        output = info.get("output_file")
        status = info.get("status", "unknown")
        executions.append({
            "name": name,
            "version": info.get("version") or meta.get("tools", {}).get(name, {}).get("version", "unknown"),
            "status": status,
            "status_class": "ok" if status == "done" else "bad" if status == "failed" else "neutral",
            "duration": _duration(info.get("started_at"), info.get("finished_at")),
            "artifact": output or "—",
            "artifact_present": bool(output and (run_dir / output).is_file()),
            "error": info.get("error", {}).get("message"),
            "reason": info.get("reason"),
        })

    severity_counts = Counter(item["severity"] for item in findings)
    highest = max((item["severity"] for item in findings), key=lambda value: SEVERITY_ORDER.get(value, 0), default="none")
    limitations = []
    if excluded_surface:
        limitations.append(f"{len(excluded_surface)} discovered assets or URLs were excluded by scope.")
    if domain == "web" and not _lines(run_dir / "work" / "enumeration.live-paths.in_scope.txt"):
        limitations.append("No discovered endpoints were independently validated as live.")
    if domain == "web" and not _lines(run_dir / "work" / "enumeration.application-routes.in_scope.txt"):
        limitations.append(
            "No validated non-static application routes were discovered; SPA/API coverage may be shallow."
        )
    route_quality = []
    quality_path = run_dir / "work" / "enumeration.route-quality.json"
    if quality_path.is_file():
        try:
            route_quality = json.loads(quality_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            route_quality = []
    for item in route_quality:
        item["url"] = _display_target(str(item.get("url", "")), target_mapping)
    unconfirmed_route_urls = {
        str(item.get("url", "")).rstrip("/")
        for item in route_quality
        if item.get("disposition") in {"candidate", "rejected"}
    }
    in_scope_surface = [
        item for item in in_scope_surface
        if str(item.get("asset", "")).rstrip("/") not in unconfirmed_route_urls
    ]
    route_candidates = [
        item for item in route_quality
        if item.get("disposition") == "candidate"
        and not is_parser_artifact(str(item.get("url", "")))
    ]
    route_rejections = [
        item for item in route_quality
        if item.get("disposition") == "rejected"
        and not is_recursive_path_artifact(str(item.get("url", "")))
    ]
    api_inventory = []
    api_inventory_path = run_dir / "work" / "enumeration.api-inventory.json"
    api_inventory = _api_inventory_entries(api_inventory_path)
    for item in api_inventory:
        item["url"] = _display_target(str(item.get("url", "")), target_mapping)
        item["surface_type"] = item.get("surface_type") or surface_type(item["url"])
    # Collapse browser transport/session variants after report-safe normalization.
    api_inventory = list({
        (item.get("method"), safe_url(item.get("url", ""), canonical=True)): {
            **item, "url": safe_url(item.get("url", ""), canonical=True)
        }
        for item in api_inventory
    }.values())
    priority_rank = {"high": 0, "medium": 1, "low": 2}
    api_inventory.sort(key=lambda item: (
        priority_rank.get(item.get("review_priority", "low"), 2),
        -int(item.get("priority_score", 0)),
        str(item.get("url", "")),
        str(item.get("method") or ""),
    ))
    if route_candidates:
        limitations.append(
            f"{len(route_candidates)} responsive URLs matched the SPA soft-404 shell and remain unconfirmed."
        )
    if route_rejections:
        limitations.append(
            f"{len(route_rejections)} extracted URLs were rejected as parser or syntax artifacts."
        )
    safe_mode = domain == "web" and str(meta.get("scan_profile", "standard")) == "safe"
    if domain == "web" and meta.get("browser_assisted"):
        limitations.append(
            "Browser-assisted API capture was enabled; stored evidence excludes header values, "
            "cookies, and request/response bodies."
        )
    if domain == "web" and meta.get("rate_limit") is not None:
        limitations.append(
            f"Rate-aware scanners were capped at {meta['rate_limit']:g} requests/second and "
            "enumeration fan-out was serialized."
        )
    if safe_mode:
        disabled_tools = sorted(
            name for name, info in state.get("tools", {}).items()
            if info.get("status") == "not_applicable"
            and "disabled by Safe mode" in str(info.get("reason", ""))
        )
        if disabled_tools:
            limitations.append(
                "Safe mode intentionally disabled: " + ", ".join(disabled_tools) + "."
            )
        nuclei_origins = len(set(_lines(run_dir / "work" / "vulnerability.targets.in_scope.txt")))
        confirmed_routes = len(set(_lines(run_dir / "work" / "enumeration.application-routes.in_scope.txt")))
        limitations.append(
            f"Safe mode supplied {nuclei_origins} live origin(s) to bounded, technology-aware Nuclei scanning; "
            f"{confirmed_routes} confirmed route(s) were retained for manual review rather than individually template-scanned."
        )
    api_inventory_note = None
    if domain == "web" and not api_inventory:
        api_inventory_note = (
            "No browser-observed or statically reconstructed API operations were captured during this assessment. "
            "This means the run produced no API inventory records; it does not establish that no API surface exists."
        )
        limitations.append(api_inventory_note)
    limitations.append("Automated matches are unverified until reproduced by an analyst.")

    return {
        "meta": meta,
        "domain": domain,
        "surface": in_scope_surface,
        "surface_observations": len(surface_records),
        "route_quality": route_quality,
        "route_candidates": route_candidates,
        "route_rejections": route_rejections,
        "api_inventory": api_inventory,
        "api_inventory_note": api_inventory_note,
        "excluded_surface": excluded_surface,
        "findings": findings,
        "executions": executions,
        "coverage": _coverage(run_dir, domain, surface, findings, target_mapping),
        "severity_counts": dict(severity_counts),
        "highest_severity": highest,
        "limitations": limitations,
        "errors": meta.get("errors", {}),
        "min_severity": DEFAULT_MIN_SEVERITY,
        "targets_display": _relative_evidence(meta.get("targets_file"), run_dir),
        "scope_snapshot": meta.get("scope_snapshot", "Not recorded"),
        "scope_hash": meta.get("scope_hash", "Not recorded"),
        "assessment_profile": (
            f"Local lab / {str(meta.get('scan_profile', 'standard')).replace('-', ' ').title()}"
            if meta.get("local_lab")
            else str(meta.get("scan_profile", "standard")).replace("-", " ").title()
        ),
    }


def generate_report(run_dir: Path):
    """Generate stakeholder, technical, and compatibility report files."""
    required = [run_dir / "meta.json", run_dir / "normalized" / "findings.json"]
    for path in required:
        if not path.exists():
            raise FileNotFoundError(f"{path.name} not found")

    model = build_report_model(run_dir)
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html"]),
    )
    prefix = "network-" if model.get("domain") == "network" else ""
    technical = env.get_template(f"{prefix}technical.html.j2").render(**model)
    stakeholder = env.get_template(f"{prefix}stakeholder.html.j2").render(**model)
    (run_dir / "technical-report.html").write_text(technical, encoding="utf-8")
    (run_dir / "stakeholder-report.html").write_text(stakeholder, encoding="utf-8")
    (run_dir / "report.html").write_text(technical, encoding="utf-8")
