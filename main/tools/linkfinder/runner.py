# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief LinkFinder execution wrapper for JavaScript endpoint discovery.
#
# This module executes LinkFinder against JavaScript resources discovered
# from validated web assets. It extracts embedded endpoints and writes
# structured JSON output for downstream processing.
#
# Strategy:
# - Retrieve JavaScript files from target assets
# - Execute LinkFinder inside Docker
# - Aggregate extracted endpoints
# - Persist normalized JSON output
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import subprocess
import json
import re
import tempfile
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from main.core.tool_manifest import get_tool_config
from main.tools.linkfinder.js_reconstruction import reconstruct_javascript_urls


JS_PATTERN = re.compile(r"\.js($|\?)", re.IGNORECASE)
MAX_JAVASCRIPT_BYTES = 8 * 1024 * 1024


def _is_js_url(url: str) -> bool:
    """Determine whether a URL points to a JavaScript resource."""
    return bool(JS_PATTERN.search(url))


def _fetch_javascript(url: str) -> str | None:
    """Retrieve a bounded public bundle once for both extractors."""

    try:
        response = requests.get(url, timeout=20, allow_redirects=False)
        response.raise_for_status()
    except requests.RequestException:
        return None
    content = response.content
    if len(content) > MAX_JAVASCRIPT_BYTES:
        return None
    return content.decode(response.encoding or "utf-8", errors="replace")


def run_linkfinder(assets_file: Path, output: Path):
    """
    Execute LinkFinder against JavaScript URLs derived from assets.

    Consumes:
      - assets file (validated HTTP URLs)

    Produces:
      - JSON output containing extracted endpoint paths
    """

    endpoints: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    assets = [
        line.strip()
        for line in assets_file.read_text().splitlines()
        if line.strip()
    ]

    js_targets = [a for a in assets if _is_js_url(a)]

    if not js_targets:
        output.write_text(json.dumps({"schema_version": 3, "endpoints": []}, indent=2))
        return

    for js_url in js_targets:
        source = _fetch_javascript(js_url)
        linkfinder_input = js_url
        temporary = None
        docker_mount: list[str] = []
        if source is not None:
            temporary = tempfile.TemporaryDirectory(prefix="deadbolt-js-")
            bundle = Path(temporary.name) / "bundle.js"
            bundle.write_text(source, encoding="utf-8")
            docker_mount = ["-v", f"{bundle}:/work/bundle.js:ro"]
            linkfinder_input = "/work/bundle.js"
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                *docker_mount,
                get_tool_config("linkfinder").image,
                "-i", linkfinder_input,
                "-o", "cli"
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            continue

        for line in result.stdout.splitlines():
            candidate = line.strip().strip("'\"")
            if not candidate or candidate.startswith(("data:", "javascript:", "mailto:")):
                continue
            resolved = urlsplit(urljoin(js_url, candidate))
            if resolved.scheme.lower() not in {"http", "https"}:
                continue
            resolved_url = urlunsplit(
                (resolved.scheme, resolved.netloc, resolved.path or "/", resolved.query, "")
            )
            key = (resolved_url, candidate, js_url, "linkfinder")
            endpoints[key] = {
                "resolved_url": resolved_url,
                "raw_expression": candidate,
                "source_url": js_url,
                # LinkFinder's CLI contract does not expose JavaScript source
                # offsets. Preserve this explicitly instead of inventing one.
                "source_location": None,
                "extractor": "linkfinder",
                "evidence_status": "discovered",
                "confidence": "low",
            }
        if source is not None:
            for inferred in reconstruct_javascript_urls(source, js_url):
                key = (
                    inferred.resolved_url,
                    inferred.raw_expression,
                    inferred.source_url,
                    inferred.extractor,
                )
                endpoints[key] = {
                    "resolved_url": inferred.resolved_url,
                    "raw_expression": inferred.raw_expression,
                    "source_url": inferred.source_url,
                    "source_location": inferred.source_location,
                    "extractor": inferred.extractor,
                    "evidence_status": "inferred",
                    "confidence": "medium",
                    "method": inferred.method,
                    "request_body_fields": list(inferred.request_body_fields),
                    "request_body_schema": [
                        {
                            "name": field.name,
                            "data_type": field.data_type,
                            "required": field.required,
                            "source": field.source,
                        }
                        for field in inferred.request_body_schema
                    ],
                    "response_fields": list(inferred.response_fields),
                    "client_validation_rules": list(inferred.client_validation_rules),
                    "request_header_names": list(inferred.request_header_names),
                    "credentials_mode": inferred.credentials_mode,
                    "wrapper_chain": list(inferred.wrapper_chain),
                }
        if temporary is not None:
            temporary.cleanup()

    output.write_text(
        json.dumps({
            "schema_version": 3,
            "endpoints": [endpoints[key] for key in sorted(endpoints)],
        }, indent=2),
        encoding="utf-8",
    )
