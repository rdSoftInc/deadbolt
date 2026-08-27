# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief Web domain scan orchestration for Deadbolt.
#
# This module implements the web scanning pipeline. It coordinates discovery,
# enumeration, and vulnerability analysis tools using a phase-based execution
# model with explicit artifact ownership, resumable state, and scope
# enforcement.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import json
import hashlib
import re
import tempfile
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, List
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from main.core.execution_table import ExecutionTable
from main.core.metadata import write_metadata
from main.core.scope import classify_target_scope, filter_in_scope, load_scope, validate_targets
from main.core.tool_manifest import get_tool_config
from main.execution.version_cache import get_fresh_cached_versions
from main.schema.normalize import Finding
from main.schema.api_evidence import (
    ApiEvidence,
    ApiInventory,
    ApiParameter,
    ApiProvenance,
    RequestSchemaConflict,
)
from main.schema.api_classification import classify_api_evidence
from main.schema.response_intelligence import (
    enrich_response_intelligence,
    infrastructure_cookie_names,
)
from main.report.generator import generate_report
from main.domains.web.runtime_registry import TOOL_RUNTIMES
from main.domains.web.tool_registry import TOOL_REGISTRY, ToolSpec
from main.domains.web.profiles import WebScanProfile, normalize_web_profile

from main.utils.resume import _resolve_run_base, resolve_scope_snapshot
from main.utils.state import hash_file, load_state, save_state
from main.utils.targets import _extract_domains_from_targets
from main.utils.local_lab import (
    DOCKER_HOST,
    normalize_local_lab_targets,
    preflight_local_lab_targets,
)
from main.utils.url_hygiene import (
    is_non_api_namespace,
    is_parser_artifact,
    safe_url,
    surface_type,
)
from main.utils.worklists import (
    _findings_to_work_items,
    _write_or_merge_worklist_txt,
)


# Ordered execution phases for web analysis
PHASE_ORDER = ["discovery", "enumeration", "vulnerability"]

_UUID_VALUE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_PATH_PLACEHOLDER = re.compile(
    r"^(?:\{([A-Za-z_$][\w$]*)(?::([A-Za-z]+))?\}|"
    r":([A-Za-z_$][\w$]*)|\[([A-Za-z_$][\w$]*)\]|"
    r"<([A-Za-z_$][\w$]*)>)$"
)


def _value_type(value: str) -> str | None:
    """Infer a structural scalar type without retaining the supplied value."""

    if not value:
        return None
    if value.lower() in {"true", "false"}:
        return "boolean"
    if re.fullmatch(r"-?\d+", value):
        return "integer"
    if re.fullmatch(r"-?(?:\d+\.\d+|\d+[eE][+-]?\d+)", value):
        return "number"
    if _UUID_VALUE.fullmatch(value):
        return "uuid"
    return "string"


def _query_schema(parsed, source: str) -> list[ApiParameter]:
    observed: dict[str, set[str | None]] = {}
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        observed.setdefault(name, set()).add(_value_type(value))
    return [
        ApiParameter(
            name=name,
            location="query",
            data_type=next(iter(types)) if len(types) == 1 else None,
            source=source,
        )
        for name, types in observed.items()
    ]


def _path_schema(path: str, source: str) -> list[ApiParameter]:
    parameters: list[ApiParameter] = []
    type_aliases = {"int": "integer", "float": "number", "bool": "boolean"}
    for index, raw_segment in enumerate(segment for segment in path.split("/") if segment):
        segment = unquote(raw_segment)
        placeholder = _PATH_PLACEHOLDER.fullmatch(segment)
        if placeholder:
            name = next(
                value for value in (
                    placeholder.group(1), placeholder.group(3),
                    placeholder.group(4), placeholder.group(5),
                ) if value
            )
            raw_type = placeholder.group(2)
            parameters.append(ApiParameter(
                name=name,
                location="path",
                data_type=type_aliases.get(raw_type, raw_type) if raw_type else None,
                required=True,
                source=source,
            ))
        elif _UUID_VALUE.fullmatch(segment):
            parameters.append(ApiParameter(
                name=f"path_segment_{index + 1}",
                location="path",
                data_type="uuid",
                required=True,
                source=source,
            ))
    return parameters

# Ensures producers run before consumers within a phase
CONSUME_RANK = {
    "targets": 0,
    "assets": 1,
    "paths": 2,
    "scan_targets": 3,
    "findings": 4,
}

ENUMERATION_FANOUT = [
    "gau",
    "waybackurls",
    "katana",
    "hakrawler",
    "ffuf",
    "paramspider",
    "graphql-cop",
    "arjun",
]
WEB_PARALLEL_WORKERS = 3
LOCAL_LAB_NOT_APPLICABLE = {"subfinder", "dnsx", "naabu", "tlsx", "gau", "waybackurls", "paramspider"}
SAFE_NOT_APPLICABLE = {"naabu", "tlsx", "ffuf", "graphql-cop", "arjun", "hakrawler"}
STATIC_RESOURCE_EXTENSIONS = {
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".avif", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".webm", ".pdf", ".zip", ".gz", ".tar",
}
SUSPICIOUS_ROUTE_MARKERS = {
    "callexpression", "memberexpression", "propertyname", "classdeclaration",
    "variabledefinition", "functiondeclaration", "jsxbuiltin", "jsxidentifier",
    "newexpression", "variablename", "application/x-www-form-urlencoded",
}


def _read_worklist(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write_worklist(path: Path, items: List[str]) -> None:
    """Overwrite one immutable stage artifact with stable deduplicated values."""

    path.parent.mkdir(parents=True, exist_ok=True)
    unique = list(dict.fromkeys(item.strip() for item in items if item and item.strip()))
    path.write_text("".join(f"{item}\n" for item in unique), encoding="utf-8")


def _merge_worklists(destination: Path, sources: List[Path]) -> Path:
    _write_worklist(destination, [item for source in sources for item in _read_worklist(source)])
    return destination


def _scope_worklist(source: Path, destination: Path, rejected_path: Path, scope: dict) -> Path:
    accepted, rejected = filter_in_scope(_read_worklist(source), scope)
    _write_worklist(destination, accepted)
    if rejected:
        _write_or_merge_worklist_txt(rejected_path, rejected)
    return destination


def _is_static_resource(value: str) -> bool:
    """Classify ordinary static resources that should not be Nuclei targets."""

    path = urlsplit(value).path.lower().rstrip("/")
    if "assets" in {segment for segment in path.split("/") if segment}:
        return True
    suffix = Path(path).suffix.lower()
    return suffix in STATIC_RESOURCE_EXTENSIONS


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), "", "", ""))


def _soft404_canaries(roots: Path) -> list[str]:
    """Create one stable, impossible-looking path per live origin."""

    canaries = []
    for root in _read_worklist(roots):
        origin = _origin(root)
        if not origin:
            continue
        token = hashlib.sha256(origin.encode("utf-8")).hexdigest()[:16]
        canaries.append(f"{origin}/.deadbolt-not-found-{token}")
    return list(dict.fromkeys(canaries))


def _nuclei_target_sources(
    profile: WebScanProfile,
    live_assets: Path,
    application_routes: Path,
) -> list[Path]:
    """Select Nuclei inputs without multiplying Safe-mode template traffic.

    Standard and Deep retain route-aware scanning. Safe applies non-intrusive
    templates once per live origin; confirmed routes remain available as
    evidence and for deliberate manual review.
    """

    if profile is WebScanProfile.SAFE:
        return [live_assets]
    return [live_assets, application_routes]


def _response_signature(finding: Finding) -> tuple:
    """Return stable HTTP characteristics used for SPA-shell comparison."""

    metadata = finding.metadata or {}
    location = metadata.get("location")
    normalized_location = (
        safe_url(str(location), canonical=True) if location else ""
    )
    return (
        finding.status_code,
        str(metadata.get("content_type") or "").split(";", 1)[0].lower(),
        int(metadata.get("content_length") or 0),
        normalized_location,
        str(metadata.get("page_type") or "").lower(),
    )


def _suspicious_route(value: str) -> bool:
    decoded = urlsplit(value).path.lower()
    if "`" in value or any(marker in decoded for marker in SUSPICIOUS_ROUTE_MARKERS):
        return True
    if is_parser_artifact(value):
        return True
    segments = [segment for segment in decoded.split("/") if segment]
    if len(segments) == 1 and segments[0].isdigit():
        return True
    return any(len(segment) > 80 for segment in segments)


def _route_quality_gate(
    *,
    findings: list[Finding],
    canaries: set[str],
    roots: set[str],
    sources: dict[str, set[str]],
    work_dir: Path,
) -> tuple[list[Finding], list[str]]:
    """Classify probed URLs and return non-canary evidence plus confirmed routes."""

    canary_signatures: dict[str, set[tuple]] = {}
    for finding in findings:
        if finding.asset not in canaries:
            continue
        canary_signatures.setdefault(_origin(finding.asset), set()).add(
            _response_signature(finding)
        )
    retained: list[Finding] = []
    confirmed: list[str] = []
    candidates: list[str] = []
    rejected: list[str] = []
    decisions: list[dict] = []

    for finding in findings:
        url = finding.asset
        if url in canaries:
            continue
        retained.append(finding)
        observed_by = sorted(sources.get(url, set()))
        disposition = "confirmed"
        confidence = "medium"
        reason = "distinct live response"

        if url in roots:
            disposition, confidence, reason = "excluded", "high", "live root scanned separately"
        elif _is_static_resource(url):
            disposition, confidence, reason = "excluded", "high", "static resource"
        elif _suspicious_route(url):
            disposition, confidence, reason = "rejected", "high", "parser or syntax artifact"
        elif _response_signature(finding) in canary_signatures.get(_origin(url), set()):
            disposition, confidence, reason = "candidate", "low", "matches SPA soft-404 shell"
        elif "ffuf" in observed_by:
            confidence, reason = "high", "content discovery response differs from soft-404"
        elif finding.status_code in {401, 403, 405}:
            confidence, reason = "high", "authorization or method boundary confirms route"
        elif str(finding.metadata.get("content_type") or "").split(";", 1)[0].lower() not in {
            "", "text/html", "application/xhtml+xml"
        }:
            confidence, reason = "high", "non-HTML response differs from SPA shell"

        decision = {
            "url": url,
            "disposition": disposition,
            "confidence": confidence,
            "reason": reason,
            "sources": observed_by,
            "status_code": finding.status_code,
            "content_type": finding.metadata.get("content_type"),
            "content_length": finding.metadata.get("content_length"),
        }
        decisions.append(decision)
        if disposition == "confirmed":
            confirmed.append(url)
        elif disposition == "candidate":
            candidates.append(url)
        elif disposition == "rejected":
            rejected.append(f"{url}\t{reason}")

    _write_worklist(work_dir / "enumeration.routes.confirmed.txt", confirmed)
    _write_worklist(work_dir / "enumeration.routes.candidates.txt", candidates)
    _write_worklist(work_dir / "enumeration.routes.rejected.tsv", rejected)
    (work_dir / "enumeration.route-quality.json").write_text(
        json.dumps(decisions, indent=2), encoding="utf-8"
    )
    return retained, list(dict.fromkeys(confirmed))


def _write_api_inventory(
    findings: list[Finding],
    work_dir: Path,
    scope: dict | None = None,
) -> list[dict]:
    """Persist merged browser and JavaScript API discovery evidence."""

    _write_browser_request_capture(findings, work_dir, scope)

    quality_path = work_dir / "enumeration.route-quality.json"
    decisions = json.loads(quality_path.read_text(encoding="utf-8")) if quality_path.is_file() else []
    quality = {item.get("url"): item for item in decisions}
    inventory: dict[tuple[str | None, str], ApiEvidence] = {}

    def merge_static_context(target: ApiEvidence, source: ApiEvidence) -> None:
        """Merge reconstruction context without weakening observed evidence."""

        for provenance_item in source.provenance:
            if provenance_item not in target.provenance:
                target.provenance.append(provenance_item)
        if not target.raw_expression:
            target.raw_expression = source.raw_expression
        for attribute in ("query_parameters", "path_parameters"):
            target_values = getattr(target, attribute)
            by_name = {value.name: value for value in target_values}
            for inferred in getattr(source, attribute):
                observed = by_name.get(inferred.name)
                if observed is None:
                    target_values.append(inferred)
                    by_name[inferred.name] = inferred
                    continue
                if observed.data_type is None and inferred.data_type is not None:
                    observed.data_type = inferred.data_type
                elif (
                    observed.data_type is not None
                    and inferred.data_type is not None
                    and observed.data_type != inferred.data_type
                ):
                    conflict = RequestSchemaConflict(
                        field_name=inferred.name,
                        location=inferred.location,
                        attribute="data_type",
                        observed=observed.data_type,
                        inferred=inferred.data_type,
                    )
                    if conflict not in target.request_schema_conflicts:
                        target.request_schema_conflicts.append(conflict)
        target_body = {field.name: field for field in target.request_body_fields}
        for inferred in source.request_body_fields:
            observed = target_body.get(inferred.name)
            if observed is None:
                target.request_body_fields.append(inferred)
                target_body[inferred.name] = inferred
                continue
            for attribute in ("data_type", "required"):
                observed_value = getattr(observed, attribute)
                inferred_value = getattr(inferred, attribute)
                if observed_value is None and inferred_value is not None:
                    setattr(observed, attribute, inferred_value)
                elif (
                    observed_value is not None
                    and inferred_value is not None
                    and observed_value != inferred_value
                ):
                    conflict = RequestSchemaConflict(
                        field_name=inferred.name,
                        location="body",
                        attribute=attribute,
                        observed=str(observed_value).lower()
                        if isinstance(observed_value, bool) else str(observed_value),
                        inferred=str(inferred_value).lower()
                        if isinstance(inferred_value, bool) else str(inferred_value),
                    )
                    if conflict not in target.request_schema_conflicts:
                        target.request_schema_conflicts.append(conflict)
        for attribute in (
            "request_header_names", "response_fields",
            "client_validation_rules", "wrapper_chain",
        ):
            setattr(target, attribute, list(dict.fromkeys([
                *getattr(target, attribute), *getattr(source, attribute),
            ])))
        if not target.credentials_mode:
            target.credentials_mode = source.credentials_mode
        target.preflight_observed = (
            target.preflight_observed or source.preflight_observed
        )
    response_enrichment: dict[tuple[str, str], Finding] = {}
    origin_enrichment: dict[str, Finding] = {}
    for finding in findings:
        if finding.tool != "httpx":
            continue
        normalized = safe_url(finding.asset, canonical=True)
        response_method = str(
            (finding.metadata or {}).get("method") or "GET"
        ).upper()
        response_enrichment[(response_method, normalized)] = finding
        parsed = urlsplit(normalized)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
        origin_enrichment.setdefault(origin, finding)
    for finding in findings:
        if finding.tool == "httpx":
            continue
        metadata = finding.metadata or {}
        methods = list(dict.fromkeys(
            str(method).upper()
            for method in [metadata.get("method"), *metadata.get("methods", [])]
            if method
        ))
        preflight_observed = "OPTIONS" in methods
        if preflight_observed and len(methods) > 1:
            methods = [method for method in methods if method != "OPTIONS"]
        elif methods == ["OPTIONS"]:
            methods = []
        observed_url = safe_url(finding.asset, canonical=True)
        parsed_observed = urlsplit(observed_url)
        canonical_url = urlunsplit((
            parsed_observed.scheme, parsed_observed.netloc,
            parsed_observed.path, "", "",
        ))
        path = parsed_observed.path.lower()
        is_api_path = any(
            marker in path
            for marker in ("/api", "/rest", "/graphql", "/gql", "/oauth", "/auth")
        )
        decision = quality.get(finding.asset, {})
        if finding.tool != "linkfinder" and decision.get("disposition") in {
            "candidate", "excluded", "rejected",
        }:
            continue
        if finding.tool != "linkfinder" and (
            is_parser_artifact(canonical_url)
            or surface_type(canonical_url) == "static resource"
        ):
            continue
        if finding.tool == "linkfinder":
            if is_non_api_namespace(canonical_url) or is_parser_artifact(canonical_url):
                continue
            evidence_status = metadata.get("evidence_status", "discovered")
            confidence = metadata.get("confidence", "low")
            if evidence_status not in {"inferred", "discovered"}:
                evidence_status = "discovered"
            if confidence not in {"medium", "low"}:
                confidence = "low"
            provenance_items = metadata.get("provenance") or [{
                "source_url": metadata.get("source_url"),
                "source_location": metadata.get("source_location"),
                "raw_expression": metadata.get("raw_expression"),
                "extractor": metadata.get("extractor", "linkfinder"),
            }]
            provenance = [
                ApiProvenance(
                    source=str(item.get("extractor") or "linkfinder"),
                    artifact=finding.evidence_path,
                    source_url=item.get("source_url"),
                    source_location=item.get("source_location"),
                    raw_expression=item.get("raw_expression"),
                )
                for item in provenance_items
                if isinstance(item, dict)
            ]
            for method in methods or [None]:
                body_fields = metadata.get("request_body_fields_by_method", {}).get(
                    method, metadata.get("request_body_fields", [])
                ) if method else metadata.get("request_body_fields", [])
                body_schema = {
                    str(item.get("name")): item
                    for item in metadata.get("request_body_schema", [])
                    if isinstance(item, dict) and item.get("name")
                }
                candidate = ApiEvidence(
                    method=method,
                    url=canonical_url,
                    raw_url=finding.asset,
                    raw_expression=metadata.get("raw_expression"),
                    evidence_status=evidence_status,
                    confidence=confidence,
                    scope_status=classify_target_scope(canonical_url, scope) if scope else "unknown",
                    source="javascript-static-reconstruction"
                    if evidence_status == "inferred" else "javascript-string-discovery",
                    provenance=provenance,
                    query_parameters=_query_schema(
                        parsed_observed, "JavaScript-discovered URL"
                    ),
                    path_parameters=_path_schema(
                        parsed_observed.path, "JavaScript-discovered URL"
                    ),
                    request_body_fields=[
                        ApiParameter(
                            name=str(name),
                            location="body",
                            data_type=body_schema.get(str(name), {}).get("data_type"),
                            required=body_schema.get(str(name), {}).get("required"),
                            source=body_schema.get(str(name), {}).get(
                                "source", "JavaScript request object"
                            ),
                        )
                        for name in dict.fromkeys(body_fields)
                        if name
                    ],
                    request_header_names=[
                        str(name) for name in metadata.get("request_header_names", []) if name
                    ],
                    response_fields=[
                        str(name) for name in metadata.get("response_fields", []) if name
                    ],
                    client_validation_rules=[
                        str(rule) for rule in metadata.get("client_validation_rules", []) if rule
                    ],
                    credentials_mode=metadata.get("credentials_mode"),
                    wrapper_chain=[
                        str(name) for name in metadata.get("wrapper_chain", []) if name
                    ],
                    preflight_observed=preflight_observed,
                    route_disposition="inferred" if evidence_status == "inferred" else "discovered",
                    route_confidence=confidence,
                    surface_type=surface_type(canonical_url),
                )
                key = (method, canonical_url)
                existing = inventory.get(key)
                if existing and existing.evidence_status == "observed":
                    merge_static_context(existing, candidate)
                else:
                    inventory[key] = candidate
            continue
        for method in methods:
            if method == "GET" and not is_api_path:
                continue
            key = (method, canonical_url)
            previous = inventory.get(key)
            observation_types = metadata.get("observation_types", [
                metadata.get("observation_type", "crawl")
            ])
            browser_source = (
                "katana-browser-xhr" if "xhr" in observation_types else "katana-browser"
            )
            response_metadata = metadata.get(
                "response_metadata_by_method", {}
            ).get(method, {})
            if not response_metadata and len(methods) == 1:
                response_metadata = metadata
            observed = ApiEvidence(
                method=method,
                url=canonical_url,
                evidence_status="observed",
                confidence="high",
                scope_status=classify_target_scope(canonical_url, scope) if scope else "unknown",
                source=browser_source,
                provenance=[ApiProvenance(
                    source=browser_source,
                    artifact=finding.evidence_path,
                    source_url=canonical_url,
                )],
                query_parameters=_query_schema(
                    parsed_observed, "browser-observed URL"
                ),
                path_parameters=_path_schema(
                    parsed_observed.path, "browser-observed URL"
                ),
                request_body_fields=[
                    ApiParameter(
                        name=str(item["name"]),
                        location="body",
                        data_type=item.get("data_type"),
                        required=item.get("required"),
                        source=item.get("source", "browser-observed request body"),
                    )
                    for item in metadata.get(
                        "request_body_schema_by_method", {}
                    ).get(method, [])
                    if isinstance(item, dict) and item.get("name")
                ],
                status_code=response_metadata.get("status_code"),
                response_content_type=response_metadata.get("content_type"),
                request_header_names=response_metadata.get(
                    "request_header_names", metadata.get("request_header_names", [])
                ),
                response_header_names=response_metadata.get("response_header_names", []),
                api_version_indicators=response_metadata.get("api_version_indicators", []),
                infrastructure_cookie_names=infrastructure_cookie_names(
                    response_metadata.get("cookie_names", [])
                ),
                preflight_observed=preflight_observed,
                route_disposition="observed",
                route_confidence="high",
                surface_type=surface_type(canonical_url),
            )
            if previous:
                merge_static_context(observed, previous)
            inventory[key] = observed
    for key in [key for key in inventory if key[0] is None]:
        discovered = inventory[key]
        observed = [
            item for item_key, item in inventory.items()
            if item_key[0] is not None and item_key[1] == key[1]
        ]
        if not observed:
            continue
        for item in observed:
            merge_static_context(item, discovered)
        del inventory[key]
    entries = []
    for key in sorted(inventory, key=lambda item: (item[1], item[0] or "")):
        evidence = inventory[key]
        method_enrichment = response_enrichment.get(
            (evidence.method or "GET", evidence.url)
        )
        enrichment = method_enrichment
        if enrichment is None:
            parsed = urlsplit(evidence.url)
            origin = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
            enrichment = origin_enrichment.get(origin)
        if enrichment is not None:
            if method_enrichment is not None:
                if evidence.status_code is None:
                    evidence.status_code = method_enrichment.status_code
                if not evidence.response_content_type:
                    evidence.response_content_type = method_enrichment.metadata.get(
                        "content_type"
                    )
            enrich_response_intelligence(
                evidence,
                technologies=enrichment.technologies,
                webserver=enrichment.webserver,
                cdn_name=enrichment.cdn_name,
            )
        else:
            enrich_response_intelligence(evidence)
        entries.append(classify_api_evidence(evidence))
    artifact = ApiInventory(entries=entries)
    (work_dir / "enumeration.api-inventory.json").write_text(
        json.dumps(artifact.model_dump(mode="json", exclude_none=True), indent=2), encoding="utf-8"
    )
    return [entry.model_dump(mode="json", exclude_none=True) for entry in entries]


def _write_browser_request_capture(
    findings: list[Finding],
    work_dir: Path,
    scope: dict | None,
) -> None:
    """Write a value-free browser request ledger separate from API inference."""

    requests: list[dict] = []
    preflights: list[dict] = []
    for finding in findings:
        if finding.tool != "katana":
            continue
        metadata = finding.metadata or {}
        methods = list(dict.fromkeys(
            str(method).upper()
            for method in [metadata.get("method"), *metadata.get("methods", [])]
            if method
        ))
        if not methods:
            continue
        normalized = safe_url(finding.asset, canonical=True)
        parsed = urlsplit(normalized)
        canonical_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        common = {
            "url": canonical_url,
            "scope_status": classify_target_scope(canonical_url, scope) if scope else "unknown",
            "observation_types": metadata.get("observation_types", [
                metadata.get("observation_type", "crawl")
            ]),
            "query_parameter_names": list(dict.fromkeys(
                name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
            )),
            "query_parameters": [
                item.model_dump(mode="json", exclude_none=True)
                for item in _query_schema(parsed, "browser-observed URL")
            ],
            "path_parameters": [
                item.model_dump(mode="json", exclude_none=True)
                for item in _path_schema(parsed.path, "browser-observed URL")
            ],
            "status_code": metadata.get("status_code"),
            "response_content_type": metadata.get("content_type"),
            "request_header_names": metadata.get("request_header_names", []),
            "request_body_schema_by_method": {
                method: schema
                for method, schema in metadata.get(
                    "request_body_schema_by_method", {}
                ).items()
                if isinstance(schema, list)
            },
            "response_header_names": metadata.get("response_header_names", []),
            "api_version_indicators": metadata.get("api_version_indicators", []),
            "infrastructure_cookie_names": infrastructure_cookie_names(
                metadata.get("cookie_names", [])
            ),
            "source": "katana-browser",
            "artifact": finding.evidence_path,
        }
        if "OPTIONS" in methods:
            preflights.append({**common, "method": "OPTIONS"})
        application_methods = [method for method in methods if method != "OPTIONS"]
        for method in application_methods:
            requests.append({
                **common,
                "method": method,
                "preflight_observed": "OPTIONS" in methods,
            })
    payload = {
        "schema_version": 1,
        "requests": sorted(requests, key=lambda item: (item["url"], item["method"])),
        "preflights": sorted(preflights, key=lambda item: item["url"]),
        "privacy": "names and response metadata only; request/response values are not stored",
    }
    (work_dir / "enumeration.browser-requests.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )


def _active_linkfinder_findings(findings: list[Finding]) -> list[Finding]:
    """Keep inferred-only JavaScript URLs out of active probe worklists."""

    return [
        finding for finding in findings
        if finding.metadata.get("evidence_status") != "inferred"
        or any(
            item.get("evidence_status") == "discovered"
            for item in finding.metadata.get("provenance", [])
            if isinstance(item, dict)
        )
    ]


def _execution_fingerprint(
    tool_name: str,
    spec: ToolSpec,
    scan_profile: WebScanProfile = WebScanProfile.STANDARD,
    browser_assisted: bool = False,
    rate_limit: float | None = None,
) -> str:
    """Hash runtime behavior relevant to safe artifact reuse."""

    runtime = TOOL_RUNTIMES[tool_name]
    physical_tool = "httpx" if tool_name == "httpx_paths" else tool_name
    configured_version = get_tool_config(physical_tool).display_version
    payload = {
        "tool": tool_name,
        "image": spec.image,
        "configured_version": configured_version,
        "runtime_revision": runtime.revision,
    }
    if tool_name in {"katana", "ffuf", "httpx", "httpx_paths", "nuclei", "naabu", "arjun"}:
        payload["scan_profile"] = scan_profile.value
        payload["rate_limit"] = rate_limit
    if tool_name == "katana":
        payload["browser_assisted"] = browser_assisted
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------
# Tool execution helper
# ---------------------------------------------------------------------

def run_tool(
    *,
    spec: ToolSpec,
    table: ExecutionTable,
    input_file: Path,
    base_dir: Path,
    scan_profile: WebScanProfile = WebScanProfile.STANDARD,
    browser_assisted: bool = False,
    rate_limit: float | None = None,
) -> List[Finding]:
    """
    Execute a single web analysis tool.

    This helper resolves the tool runtime, executes the tool against the
    provided input artifact, parses findings, and applies any optional
    post-processing hooks.
    """
    table.tool_started(spec.name)

    runtime = TOOL_RUNTIMES.get(spec.name)
    if not runtime:
        raise RuntimeError(f"No runtime registered for {spec.name}")

    raw_name = runtime.raw_subdir or spec.name
    raw_dir = base_dir / "raw" / raw_name
    raw_dir.mkdir(parents=True, exist_ok=True)

    output = raw_dir / runtime.output_name

    # Tools write into a run-owned staging directory. Existing evidence is
    # left untouched until both execution and parsing succeed, preventing
    # stale output reuse and preserving the last valid artifact on failure.
    with tempfile.TemporaryDirectory(prefix=".deadbolt-stage-", dir=raw_dir) as staging:
        staging_dir = Path(staging)
        staged_output = staging_dir / runtime.output_name
        if spec.name == "katana":
            runtime.runner(
                input_file, staged_output, profile=scan_profile,
                browser_assisted=browser_assisted, rate_limit=rate_limit,
            )
        elif spec.name in {"ffuf", "httpx", "httpx_paths", "nuclei", "naabu", "arjun"}:
            runtime.runner(
                input_file, staged_output, profile=scan_profile, rate_limit=rate_limit,
            )
        else:
            runtime.runner(input_file, staged_output)
        if not staged_output.is_file():
            raise RuntimeError(f"{spec.name} did not produce {runtime.output_name}")
        findings = runtime.parser(staged_output)

        if runtime.postprocess:
            runtime.postprocess(findings)

        staged_files = [path for path in staging_dir.iterdir() if path.is_file()]
        published_names = {path.name for path in staged_files}
        for existing in raw_dir.iterdir():
            if existing.is_file() and existing.name not in published_names:
                existing.unlink()
        for staged_file in staged_files:
            staged_file.replace(raw_dir / staged_file.name)

    # Parsers saw the staged path; reports must reference the durable artifact.
    for finding in findings:
        finding.evidence_path = str(output)

    return findings


# ---------------------------------------------------------------------
# Main scan runner
# ---------------------------------------------------------------------

def run_web(
    targets_path: str,
    resume_from: Optional[Path] = None,
    local_lab: bool = False,
    scan_profile: WebScanProfile | str = WebScanProfile.STANDARD,
    scope_path: Optional[Path] = None,
    browser_assisted: bool = False,
    rate_limit: float | None = None,
) -> None:
    """
    Execute the web reconnaissance and vulnerability scanning pipeline.

    This function enforces scope boundaries, initializes work artifacts,
    orchestrates tools across discovery, enumeration, and vulnerability
    phases, and persists normalized findings, metadata, and reports.

    Execution is resumable and artifact-driven: tools consume and produce
    explicit work artifacts that determine downstream execution.
    """

    targets_file = Path(targets_path)
    scan_profile = normalize_web_profile(scan_profile)
    if rate_limit is not None and rate_limit < 1:
        raise ValueError("--rate-limit must be at least 1 request per second")

    # Resume owns its original transport/profile semantics. CLI defaults must
    # never silently turn a local Deep SPA run into a public Standard scan.
    if resume_from is not None:
        resume_path = Path(resume_from).resolve()
        context = {}
        for context_file in (resume_path / "meta.json", resume_path / "state.json"):
            if not context_file.is_file():
                continue
            try:
                payload = json.loads(context_file.read_text(encoding="utf-8"))
                context = payload if context_file.name == "meta.json" else payload.get("run", {})
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if context:
                break
        local_lab = bool(context.get("local_lab", local_lab))
        scan_profile = normalize_web_profile(context.get("scan_profile", scan_profile.value))
        browser_assisted = bool(context.get("browser_assisted", browser_assisted))
        rate_limit = context.get("rate_limit", rate_limit)

    # -------------------------------
    # Hard scope enforcement
    # -------------------------------
    scope_file = Path(scope_path) if scope_path else None
    if scope_file is None and resume_from is not None:
        scope_file = resolve_scope_snapshot(Path(resume_from))
    scope_file = scope_file or Path("scope.yaml")
    local_targets = None
    if local_lab:
        local_targets = normalize_local_lab_targets(_read_worklist(targets_file))
        preflight_local_lab_targets(local_targets)
    else:
        validate_targets(targets_file=targets_file, scope_file=scope_file)

    started_at = datetime.now(timezone.utc)

    # -------------------------------
    # Resume validation
    # -------------------------------
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

    # -------------------------------
    # Output directory setup
    # -------------------------------
    base = _resolve_run_base(resume_from)
    base.mkdir(parents=True, exist_ok=True)
    run_id = base.name

    # Persistent state
    state_file = base / "state.json"
    state = load_state(state_file)
    state.setdefault("schema", 1)
    state.setdefault("tools", {})
    state["run"] = {
        "local_lab": local_lab,
        "scan_profile": scan_profile.value,
        "browser_assisted": browser_assisted,
        "rate_limit": rate_limit,
    }
    save_state(state_file, state)

    norm_dir = base / "normalized"
    work_dir = base / "work"
    norm_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    # Preserve every authorization boundary used by this run. Scope changes
    # during resume create another immutable snapshot instead of rewriting
    # historical evidence.
    source_scope = load_scope(scope_file)
    if local_lab:
        effective_scope = {
            **source_scope,
            "allow": list(dict.fromkeys([*source_scope.get("allow", []), DOCKER_HOST])),
        }
        import yaml
        scope_content = yaml.safe_dump(effective_scope, sort_keys=False)
    else:
        scope_content = scope_file.read_text(encoding="utf-8")
    scope_hash = hashlib.sha256(scope_content.encode("utf-8")).hexdigest()
    scope_dir = base / "scope"
    scope_dir.mkdir(parents=True, exist_ok=True)
    scope_snapshot = scope_dir / f"{scope_hash}.yaml"
    if not scope_snapshot.exists():
        scope_snapshot.write_text(scope_content, encoding="utf-8")
    state["scope"] = {
        "hash": scope_hash,
        "snapshot": str(scope_snapshot.relative_to(base)),
    }
    save_state(state_file, state)

    # -------------------------------
    # Initial discovery targets
    # -------------------------------
    input_snapshot = work_dir / "input.targets.txt"
    if not input_snapshot.exists():
        _write_worklist(
            input_snapshot,
            [item.canonical for item in local_targets]
            if local_targets else _read_worklist(targets_file),
        )
    if local_lab:
        # Re-normalize snapshots during resume and retain ports/base paths.
        local_targets = normalize_local_lab_targets(_read_worklist(input_snapshot))
        discovery_targets = work_dir / "targets.transport.txt"
        _write_worklist(discovery_targets, [item.transport for item in local_targets])
    else:
        domains = _extract_domains_from_targets(targets_file)
        discovery_targets = work_dir / "targets_domains.txt"
        _write_or_merge_worklist_txt(discovery_targets, domains)

    # -------------------------------
    # Execution table initialization
    # -------------------------------
    table = ExecutionTable()
    for tool in TOOL_REGISTRY.values():
        physical_tool = "httpx" if tool.name == "httpx_paths" else tool.name
        # A scan may begin before asynchronous Docker/GitHub detection completes.
        # Seed the table with the reproducible manifest pin so run metadata can
        # never persist a transient UI placeholder such as ``detecting…``.
        configured = get_tool_config(physical_tool)
        cached = get_fresh_cached_versions(tool.image)
        latest = cached[1] if cached else None
        update = (
            "latest" if latest == configured.display_version
            else f"→ {latest}" if latest
            else "pinned"
        )
        table.register_tool(tool.name, configured.display_version, update)

    # -------------------------------
    # Immutable, dependency-aware pipeline
    # -------------------------------
    all_findings: List[Finding] = []
    tool_errors: Dict[str, str] = {}
    findings_by_tool: Dict[str, List[Finding]] = {}
    state_lock = threading.Lock()
    scope = load_scope(scope_snapshot)
    rejected_scope = work_dir / "scope.rejected.txt"

    def execute(tool_name: str, input_file: Path, output_file: Path) -> List[Finding]:
        """Execute or resume one tool against an immutable input/output pair."""

        spec = TOOL_REGISTRY[tool_name]
        if not input_file.is_file() or input_file.stat().st_size == 0:
            table.tool_no_input(tool_name)
            _write_worklist(output_file, [])
            return []

        input_hash = hash_file(input_file)
        execution_fingerprint = _execution_fingerprint(
            tool_name, spec, scan_profile, browser_assisted, rate_limit,
        )
        tool_state = state["tools"].get(tool_name)
        normalized_file = norm_dir / f"{tool_name}.{spec.produces}.json"
        if (
            tool_state
            and tool_state.get("status") == "done"
            and tool_state.get("input_hash") == input_hash
            and tool_state.get("execution_fingerprint") == execution_fingerprint
            and output_file.is_file()
        ):
            resumed_findings: List[Finding] = []
            if normalized_file.is_file():
                payload = json.loads(normalized_file.read_text(encoding="utf-8"))
                resumed_findings = [Finding.model_validate(item) for item in payload]
                # Keep audit indexes self-describing, including runs created
                # before finding worklists carried compact result summaries.
                if spec.produces == "findings":
                    _write_worklist(
                        output_file,
                        _findings_to_work_items(spec.produces, resumed_findings),
                    )
                with state_lock:
                    findings_by_tool[tool_name] = resumed_findings
            duration_seconds = tool_state.get("duration_seconds")
            if duration_seconds is None:
                try:
                    started = datetime.fromisoformat(tool_state["started_at"])
                    finished = datetime.fromisoformat(tool_state["finished_at"])
                    duration_seconds = (finished - started).total_seconds()
                except (KeyError, TypeError, ValueError):
                    duration_seconds = None
            result_count = tool_state.get("result_count")
            if result_count is None and normalized_file.is_file():
                result_count = len(resumed_findings)
            table.tool_cached(tool_name, result_count, duration_seconds)
            return resumed_findings

        tool_started_at = datetime.now(timezone.utc)
        try:
            run_arguments = dict(
                spec=spec,
                table=table,
                input_file=input_file,
                base_dir=base,
                scan_profile=scan_profile,
            )
            if browser_assisted:
                run_arguments["browser_assisted"] = True
            if rate_limit is not None:
                run_arguments["rate_limit"] = rate_limit
            findings = run_tool(**run_arguments)
        except Exception as exc:
            table.tool_failed(tool_name)
            error_message = str(exc)
            with state_lock:
                tool_errors[tool_name] = error_message
                state["tools"][tool_name] = {
                    "status": "failed",
                    "version": table.versions.get(tool_name),
                    "input_type": spec.consumes,
                    "input_hash": input_hash,
                    "execution_fingerprint": execution_fingerprint,
                    "started_at": tool_started_at.isoformat(),
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                    "error": {
                        "type": type(exc).__name__,
                        "message": error_message,
                        "trace": traceback.format_exc(limit=5),
                    },
                }
                save_state(state_file, state)
            _write_worklist(output_file, [])
            with state_lock:
                findings_by_tool[tool_name] = []
            return []

        tool_finished_at = datetime.now(timezone.utc)
        duration_seconds = (tool_finished_at - tool_started_at).total_seconds()
        table.tool_finished(tool_name, len(findings))
        normalized_file.write_text(
            json.dumps([finding.model_dump() for finding in findings], indent=2, default=str),
            encoding="utf-8",
        )
        worklist_findings = findings
        if tool_name == "linkfinder":
            # Static reconstruction is evidence for analyst review. It must
            # not silently widen active probing beyond LinkFinder's existing
            # string-discovery worklist.
            worklist_findings = _active_linkfinder_findings(findings)
        _write_worklist(
            output_file,
            _findings_to_work_items(spec.produces, worklist_findings),
        )
        with state_lock:
            findings_by_tool[tool_name] = findings
            state["tools"][tool_name] = {
                "status": "done",
                "version": table.versions.get(tool_name),
                "input_type": spec.consumes,
                "input_hash": input_hash,
                "execution_fingerprint": execution_fingerprint,
                "output_type": spec.produces,
                "output_file": str(output_file.relative_to(base)),
                "normalized_file": str(normalized_file.relative_to(base)),
                "started_at": tool_started_at.isoformat(),
                "finished_at": tool_finished_at.isoformat(),
                "duration_seconds": duration_seconds,
                "result_count": len(findings),
            }
            save_state(state_file, state)
        return findings

    def mark_not_applicable(tool_name: str, output_file: Path, reason: str) -> None:
        table.tool_not_applicable(tool_name)
        _write_worklist(output_file, [])
        with state_lock:
            state["tools"][tool_name] = {
                "status": "not_applicable",
                "reason": reason,
                "output_file": str(output_file.relative_to(base)),
            }
            save_state(state_file, state)

    table.start()
    try:
        # Internet discovery expands DNS; local labs preserve the supplied URL
        # and port and begin directly with HTTP validation.
        discovered = work_dir / "discovery.subfinder.domains.txt"
        resolved = work_dir / "discovery.dnsx.resolved.txt"
        if local_lab:
            mark_not_applicable("subfinder", discovered, "not applicable to local-lab mode")
            mark_not_applicable("dnsx", resolved, "not applicable to local-lab mode")
            ports = work_dir / "discovery.naabu.services.txt"
            mark_not_applicable("naabu", ports, "not applicable to local-lab mode")
            mark_not_applicable("tlsx", work_dir / "discovery.tlsx.services.txt", "not applicable to local-lab mode")
            scoped_resolved = _scope_worklist(
                discovery_targets,
                work_dir / "discovery.resolved.in_scope.txt",
                rejected_scope,
                scope,
            )
        else:
            execute("subfinder", discovery_targets, discovered)
            candidate_domains = _merge_worklists(
                work_dir / "discovery.domains.merged.txt",
                [discovery_targets, discovered],
            )
            scoped_domains = _scope_worklist(
                candidate_domains,
                work_dir / "discovery.domains.in_scope.txt",
                rejected_scope,
                scope,
            )
            execute("dnsx", scoped_domains, resolved)
            scoped_resolved = _scope_worklist(
                resolved,
                work_dir / "discovery.resolved.in_scope.txt",
                rejected_scope,
                scope,
            )

            ports = work_dir / "discovery.naabu.services.txt"
            if scan_profile is WebScanProfile.SAFE:
                mark_not_applicable("naabu", ports, "disabled by Safe mode")
                mark_not_applicable("tlsx", work_dir / "discovery.tlsx.services.txt", "disabled by Safe mode")
            else:
                execute("naabu", scoped_resolved, ports)
                scoped_ports = _scope_worklist(ports, work_dir / "discovery.services.in_scope.txt", rejected_scope, scope)
                scoped_resolved = _merge_worklists(work_dir / "discovery.http-candidates.txt", [scoped_resolved, scoped_ports])
                execute("tlsx", scoped_ports, work_dir / "discovery.tlsx.services.txt")

        live_assets = work_dir / "discovery.httpx.live.txt"
        execute("httpx", scoped_resolved, live_assets)
        scoped_live_assets = _scope_worklist(
            live_assets,
            work_dir / "discovery.live.in_scope.txt",
            rejected_scope,
            scope,
        )
        # Independent enumeration producers run concurrently and never share outputs.
        enumeration_dir = work_dir / "enumeration"
        enumeration_outputs = {
            name: enumeration_dir / f"{name}.paths.txt"
            for name in ENUMERATION_FANOUT
        }
        active_enumeration = [
            name for name in ENUMERATION_FANOUT
            if not local_lab or name not in LOCAL_LAB_NOT_APPLICABLE
        ]
        if scan_profile is WebScanProfile.SAFE:
            active_enumeration = [name for name in active_enumeration if name not in SAFE_NOT_APPLICABLE]
        for name in ENUMERATION_FANOUT:
            if name not in active_enumeration:
                reason = "disabled by Safe mode" if name in SAFE_NOT_APPLICABLE else "not applicable to local-lab mode"
                mark_not_applicable(name, enumeration_outputs[name], reason)
        enumeration_workers = (
            1 if scan_profile is WebScanProfile.SAFE or rate_limit is not None
            else WEB_PARALLEL_WORKERS
        )
        with ThreadPoolExecutor(max_workers=enumeration_workers) as executor:
            futures = {
                name: executor.submit(execute, name, scoped_live_assets, output)
                for name, output in enumeration_outputs.items()
                if name in active_enumeration
            }
            for future in futures.values():
                future.result()

        merged_paths = _merge_worklists(
            work_dir / "enumeration.paths.merged.txt",
            list(enumeration_outputs.values()),
        )
        plausible_paths = [
            value for value in _read_worklist(merged_paths)
            if not is_parser_artifact(value)
        ]
        recursive_artifacts = [
            value for value in _read_worklist(merged_paths)
            if is_parser_artifact(value)
        ]
        _write_worklist(merged_paths, plausible_paths)
        _write_worklist(work_dir / "enumeration.paths.rejected-artifacts.txt", recursive_artifacts)
        scoped_paths = _scope_worklist(
            merged_paths,
            work_dir / "enumeration.paths.in_scope.txt",
            rejected_scope,
            scope,
        )

        linkfinder_paths = enumeration_dir / "linkfinder.paths.txt"
        execute("linkfinder", scoped_paths, linkfinder_paths)
        paths_with_js = _merge_worklists(
            work_dir / "enumeration.paths.with-js.txt",
            [scoped_paths, linkfinder_paths],
        )
        scoped_paths_with_js = _scope_worklist(
            paths_with_js,
            work_dir / "enumeration.paths.with-js.in_scope.txt",
            rejected_scope,
            scope,
        )

        canary_urls = _soft404_canaries(scoped_live_assets)
        validation_targets = _merge_worklists(
            work_dir / "enumeration.validation-targets.txt",
            [scoped_paths_with_js],
        )
        _write_worklist(
            validation_targets,
            [*_read_worklist(validation_targets), *canary_urls],
        )
        probed_paths = work_dir / "enumeration.httpx.probed-paths.txt"
        execute("httpx_paths", validation_targets, probed_paths)

        route_sources: dict[str, set[str]] = {}
        for producer in [*ENUMERATION_FANOUT, "linkfinder"]:
            for finding in findings_by_tool.get(producer, []):
                route_sources.setdefault(finding.asset, set()).add(producer)
        probed_findings = findings_by_tool.get("httpx_paths", [])
        retained_paths, confirmed_routes = _route_quality_gate(
            findings=probed_findings,
            canaries=set(canary_urls),
            roots=set(_read_worklist(scoped_live_assets)),
            sources=route_sources,
            work_dir=work_dir,
        )
        table.tool_result_summary(
            "httpx_paths",
            str(len(retained_paths)),
        )
        state["route_quality"] = {
            "probed": len(probed_findings),
            "responsive": len(retained_paths),
            "confirmed": len(confirmed_routes),
        }
        save_state(state_file, state)
        api_inventory = _write_api_inventory(
            [
                *findings_by_tool.get("katana", []),
                *findings_by_tool.get("linkfinder", []),
                *findings_by_tool.get("httpx", []),
                *retained_paths,
            ],
            work_dir,
            scope,
        )
        state["api_inventory"] = {"requests": len(api_inventory)}
        save_state(state_file, state)
        findings_by_tool["httpx_paths"] = retained_paths
        live_paths = work_dir / "enumeration.httpx.live-paths.txt"
        _write_worklist(live_paths, [finding.asset for finding in retained_paths])
        scoped_live_paths = _scope_worklist(
            live_paths,
            work_dir / "enumeration.live-paths.in_scope.txt",
            rejected_scope,
            scope,
        )
        # Only confirmed, non-static routes enter the vulnerability scan.
        application_routes = work_dir / "enumeration.application-routes.in_scope.txt"
        accepted_routes, rejected_routes = filter_in_scope(confirmed_routes, scope)
        _write_worklist(application_routes, accepted_routes)
        if rejected_routes:
            _write_or_merge_worklist_txt(rejected_scope, rejected_routes)

        # Safe mode scans each live origin once. Feeding every discovered URL
        # to a template scanner multiplies nearly identical requests and can
        # turn a low-rate bug-bounty assessment into hours of redundant
        # traffic. Standard/Deep retain route-aware template coverage.
        vulnerability_targets = _merge_worklists(
            work_dir / "vulnerability.targets.txt",
            _nuclei_target_sources(
                scan_profile,
                scoped_live_assets,
                application_routes,
            ),
        )
        vulnerability_targets = _scope_worklist(
            vulnerability_targets,
            work_dir / "vulnerability.targets.in_scope.txt",
            rejected_scope,
            scope,
        )
        execute(
            "nuclei",
            vulnerability_targets,
            work_dir / "vulnerability.nuclei.findings.txt",
        )
        all_findings = [
            finding
            for tool_name in TOOL_REGISTRY
            for finding in findings_by_tool.get(tool_name, [])
        ]
    finally:
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
        targets_file=targets_file,
        started_at=started_at,
        finished_at=finished_at,
        domain="web",
        tools={
            spec.name: {
                "image": spec.image,
                "version": table.versions.get(spec.name, "unknown"),
            }
            for spec in TOOL_REGISTRY.values()
        },
        errors=tool_errors,
        scope_snapshot=scope_snapshot,
        scope_hash=scope_hash,
        local_lab=local_lab,
        target_mapping={item.transport: item.canonical for item in local_targets or []},
        scan_profile=scan_profile.value,
        browser_assisted=browser_assisted,
        rate_limit=rate_limit,
    )

    generate_report(base)
