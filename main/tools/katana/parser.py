# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file parser.py
# @brief katana output parser for headless browser crawling analysis.
#
# This module parses raw katana crawler output and classifies discovered URLs
# by path patterns, parameter significance, crawl depth, and dynamic identifiers.
#
# Detects:
# - API endpoints and integrations
# - Management/admin paths
# - Dynamic resource identifiers (UUIDs, numeric IDs)
# - Sensitive query parameters
# - HTTP usage
# - Crawl depth and path nesting
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, parse_qs, parse_qsl
from typing import Tuple, List
import json
import re

from main.schema.normalize import Finding
from main.utils.url_hygiene import safe_url


# ---------------------------------------------------------------------
# Precompiled Patterns
# ---------------------------------------------------------------------

SENSITIVE_PARAMS = {
    "auth", "token", "secret", "key", "password", "passwd", "pwd",
    "api_key", "apikey", "access_token", "refresh_token",
    "session", "sid", "cookie",
    "credential", "credentials",
}

API_PATTERNS = [
    re.compile(p) for p in {
        r"/api/", r"/apis/", r"/api-",
        r"/graphql", r"/gql",
        r"/rest/", r"/service",
        r"/v\d+/", r"/v\d+-",
    }
]

ADMIN_PATTERNS = [
    re.compile(p) for p in {
        r"/admin", r"/manage", r"/console",
        r"/dashboard", r"/panel",
        r"/control", r"/settings",
    }
]

DYNAMIC_PATTERNS = [
    re.compile(r"/[a-f0-9]{8,}"),
    re.compile(r"/\d{6,}"),
    re.compile(r"/[a-zA-Z0-9]{10,}"),
]


# ---------------------------------------------------------------------
# Classification Helpers
# ---------------------------------------------------------------------

def _classify_path(path: str) -> Tuple[str, str]:
    """
    Classify path pattern and assign baseline severity.

    Returns:
        (path_type, severity)
    """
    if any(p.search(path) for p in ADMIN_PATTERNS):
        return ("admin_management", "high")

    if any(p.search(path) for p in API_PATTERNS):
        return ("api_endpoint", "medium")

    if any(p.search(path) for p in DYNAMIC_PATTERNS):
        return ("dynamic_identifier", "medium")

    return ("discovered_url", "low")


def _analyze_parameters(query: str) -> Tuple[List[str], bool]:
    """
    Analyze query parameters for sensitivity.
    """
    if not query:
        return [], False

    params = parse_qs(query, keep_blank_values=True)
    sensitive = []

    for name in params.keys():
        lower = name.lower()
        if any(keyword in lower for keyword in SENSITIVE_PARAMS):
            sensitive.append(name)

    return sensitive, bool(sensitive)


def _calculate_depth(path: str) -> int:
    """
    Calculate URL depth based on path segments.
    """
    return len([s for s in path.split("/") if s])


def _structural_type(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _request_body_schema(value) -> tuple[tuple[str, str], ...]:
    """Return value-free top-level structure from common request bodies."""

    parsed = value
    if isinstance(value, str):
        if len(value) > 1_000_000:
            return ()
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            if "=" not in value:
                return ()
            return tuple(dict.fromkeys(
                (name, "string")
                for name, _ in parse_qsl(value, keep_blank_values=True)
                if name
            ))
    if not isinstance(parsed, dict):
        return ()
    return tuple(
        (str(name), _structural_type(field_value))
        for name, field_value in parsed.items()
        if str(name)
    )


def _observed_body_schema(record: dict) -> tuple[tuple[str, str], ...]:
    for key in ("body", "request_body", "post_data", "postData", "data"):
        if key in record:
            schema = _request_body_schema(record[key])
            if schema:
                return schema
    return ()


def _json_urls(payload: dict) -> list[tuple]:
    """Extract crawled and XHR URLs/methods from Katana JSONL variants."""

    request = payload.get("request") if isinstance(payload.get("request"), dict) else {}
    base = request.get("endpoint") or request.get("url") or payload.get("url") or ""
    found: list[tuple] = []

    def walk(value, observation_type="navigation"):
        if isinstance(value, dict):
            method = value.get("method") if isinstance(value.get("method"), str) else None
            status_value = value.get("status_code", value.get("status"))
            status_code = status_value if isinstance(status_value, int) else None
            content_type = value.get("content_type")
            if not isinstance(content_type, str):
                content_type = None
            response = value.get("response") if isinstance(value.get("response"), dict) else {}
            request_headers = value.get("request_header_names", [])
            response_headers = response.get(
                "response_header_names", value.get("response_header_names", [])
            )
            versions = response.get(
                "api_version_indicators", value.get("api_version_indicators", [])
            )
            cookies = response.get("cookie_names", value.get("cookie_names", []))
            request_body_schema = _observed_body_schema(value)
            if status_code is None:
                response_status = response.get("status_code", response.get("status"))
                status_code = response_status if isinstance(response_status, int) else None
            if content_type is None:
                response_type = response.get("content_type")
                content_type = response_type if isinstance(response_type, str) else None
            for key, item in value.items():
                if key.lower() in {"url", "endpoint"} and isinstance(item, str):
                    resolved = urljoin(base, item)
                    if resolved.startswith(("http://", "https://")):
                        found.append((
                            resolved, method, observation_type, status_code, content_type,
                            tuple(request_headers) if isinstance(request_headers, list) else (),
                            tuple(response_headers) if isinstance(response_headers, list) else (),
                            tuple(versions) if isinstance(versions, list) else (),
                            tuple(cookies) if isinstance(cookies, list) else (),
                            request_body_schema,
                        ))
                else:
                    child_type = "xhr" if key.lower() in {"xhr", "fetch", "requests"} else observation_type
                    walk(item, child_type)
        elif isinstance(value, list):
            for item in value:
                walk(item, observation_type)

    walk(payload)
    return list(dict.fromkeys(found))


def _line_urls(line: str) -> list[tuple]:
    """Support standard plain output and Deep SPA JSONL output."""

    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return [(line, None, "crawl", None, None, (), (), (), (), ())]
    return _json_urls(payload) if isinstance(payload, dict) else []


# ---------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------

def parse_katana(raw_file: Path) -> List[Finding]:
    """
    Parse katana crawler output into normalized path findings.

    katana emits one URL per line discovered via headless browser crawling.
    Each URL is normalized, classified, deduplicated, and enriched with
    crawl metadata before being returned as Deadbolt Finding objects.
    """
    findings = {}
    timestamp = datetime.now(timezone.utc)

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            for (
                raw_url, method, observation_type, status_code, content_type,
                request_header_names, response_header_names, api_version_indicators,
                cookie_names, request_body_schema,
            ) in _line_urls(line):

                normalized = safe_url(raw_url, canonical=True)
                parsed = urlparse(normalized)

                if not parsed.scheme or not parsed.netloc:
                    continue

                path = parsed.path.lower()
                query = parsed.query

                path_type, baseline_severity = _classify_path(path)
                sensitive_params, has_sensitive = _analyze_parameters(query)
                depth = _calculate_depth(path)
                response_metadata = {
                    "status_code": status_code,
                    "content_type": content_type,
                    "request_header_names": list(request_header_names),
                    "response_header_names": list(response_header_names),
                    "api_version_indicators": list(api_version_indicators),
                    "cookie_names": list(cookie_names),
                    "request_body_schema": [
                        {
                            "name": name,
                            "data_type": data_type,
                            "required": None,
                            "source": "browser-observed request body",
                        }
                        for name, data_type in request_body_schema
                    ],
                }
                has_response_metadata = any(
                    value not in {None, "", ()}
                    if not isinstance(value, list) else bool(value)
                    for value in response_metadata.values()
                )

                # Severity refinement
                if has_sensitive:
                    severity = "high"
                    title = f"URL with sensitive parameters: {parsed.path}"
                elif path_type == "admin_management":
                    severity = "high"
                    title = f"Admin/management path discovered: {parsed.path}"
                elif path_type == "api_endpoint":
                    severity = "medium"
                    title = f"API endpoint discovered: {parsed.path}"
                elif path_type == "dynamic_identifier":
                    severity = "medium"
                    title = f"Dynamic resource path discovered: {parsed.path}"
                else:
                    severity = baseline_severity
                    title = f"Path discovered: {parsed.path}"

                # Flag HTTP usage
                if parsed.scheme == "http":
                    severity = "medium" if severity == "low" else severity
                    title += " [HTTP]"

                if normalized not in findings:
                    findings[normalized] = Finding(
                        asset=normalized,
                        title=title,
                        tool="katana",
                        kind="path",
                        severity=severity,
                        occurrences=1,
                        timestamp=timestamp,
                        evidence_path=str(raw_file),
                        metadata={
                            "source": "katana",
                            "path_type": path_type,
                            "path": parsed.path,
                            "query": query,
                            "domain": parsed.netloc,
                            "scheme": parsed.scheme,
                            "depth": depth,
                            "sensitive_params": sensitive_params,
                            "has_sensitive_params": has_sensitive,
                            "method": method,
                            "observation_type": observation_type,
                            "observation_types": [observation_type],
                            "status_code": status_code,
                            "content_type": content_type,
                            "request_header_names": list(request_header_names),
                            "response_header_names": list(response_header_names),
                            "api_version_indicators": list(api_version_indicators),
                            "cookie_names": list(cookie_names),
                            "request_body_schema_by_method": {
                                method.upper(): response_metadata["request_body_schema"]
                            } if method and request_body_schema else {},
                            "response_metadata_by_method": {
                                method.upper(): response_metadata
                            } if method and has_response_metadata else {},
                            "cwe": "CWE-215: Information Exposure Through Debug Information",
                        },
                    )
                else:
                    findings[normalized].occurrences += 1
                    methods = findings[normalized].metadata.setdefault("methods", [])
                    if method and method not in methods:
                        methods.append(method)
                    observation_types = findings[normalized].metadata.setdefault(
                        "observation_types", []
                    )
                    if observation_type not in observation_types:
                        observation_types.append(observation_type)
                    if status_code is not None:
                        findings[normalized].metadata["status_code"] = status_code
                    if content_type:
                        findings[normalized].metadata["content_type"] = content_type
                    if method and has_response_metadata:
                        findings[normalized].metadata.setdefault(
                            "response_metadata_by_method", {}
                        )[method.upper()] = response_metadata
                    if method and request_body_schema:
                        schemas = findings[normalized].metadata.setdefault(
                            "request_body_schema_by_method", {}
                        )
                        current_schema = schemas.setdefault(method.upper(), [])
                        for item in response_metadata["request_body_schema"]:
                            if item not in current_schema:
                                current_schema.append(item)
                    for key, values in {
                        "request_header_names": request_header_names,
                        "response_header_names": response_header_names,
                        "api_version_indicators": api_version_indicators,
                        "cookie_names": cookie_names,
                    }.items():
                        current = findings[normalized].metadata.setdefault(key, [])
                        current.extend(value for value in values if value not in current)

    # Deterministic ordering for resume stability
    return sorted(findings.values(), key=lambda f: f.asset)
