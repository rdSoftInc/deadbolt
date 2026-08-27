# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief katana execution wrapper.
#
# This module defines the execution logic for katana using a containerized
# runtime. katana performs crawling and URL discovery across target assets
# and produces a plain-text list of discovered URLs.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import json
from main.execution.docker import run_container
from main.core.tool_manifest import get_tool_config
from main.domains.web.profiles import WebScanProfile, capped_rate, normalize_web_profile, policy_for
from main.utils.url_hygiene import safe_url


SENSITIVE_EVIDENCE_FIELDS = {"raw", "body"}
SAFE_VERSION_HEADERS = {
    "api-supported-versions", "api-deprecated-versions", "x-api-version",
}


def _sanitize_jsonl(value: str) -> str:
    """Remove request/response material that may contain secrets or large bodies."""

    def header_metadata(headers, *, response: bool) -> dict:
        if not isinstance(headers, dict):
            return {}
        names = [str(name) for name in headers if name]
        result = {
            "response_header_names" if response else "request_header_names": names,
        }
        if response:
            versions = []
            cookies = []
            for name, value in headers.items():
                lower = str(name).lower()
                if lower in SAFE_VERSION_HEADERS and isinstance(value, (str, int, float)):
                    versions.append(f"{lower}: {value}")
                if lower == "set-cookie" and isinstance(value, str):
                    cookie_name = value.split(";", 1)[0].split("=", 1)[0].strip()
                    if cookie_name:
                        cookies.append(cookie_name)
            if versions:
                result["api_version_indicators"] = versions
            if cookies:
                result["cookie_names"] = cookies
        return result

    def sanitize(item, *, context: str | None = None):
        if isinstance(item, dict):
            clean = {}
            for key, child in item.items():
                lower = key.lower()
                if lower in SENSITIVE_EVIDENCE_FIELDS:
                    continue
                if lower == "headers":
                    clean.update(header_metadata(child, response=context == "response"))
                    continue
                child_context = lower if lower in {"request", "response"} else context
                clean[key] = sanitize(child, context=child_context)
            return clean
        if isinstance(item, list):
            return [sanitize(child, context=context) for child in item]
        if isinstance(item, str) and item.startswith(("http://", "https://")):
            return safe_url(item)
        return item

    records = []
    for line in value.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        records.append(json.dumps(sanitize(payload), separators=(",", ":")))
    return "".join(f"{record}\n" for record in records)


def run_katana(
    targets: Path,
    output: Path,
    *,
    profile: WebScanProfile | str = WebScanProfile.STANDARD,
    browser_assisted: bool = False,
    rate_limit: float | None = None,
):
    """
    Execute katana crawler against target assets.

    Consumes:
      - assets (domains or URLs)

    Produces:
      - paths (discovered URLs, one per line)

    Notes:
      - katana focuses on URL discovery
      - Output is plain text for easy downstream consumption
    """
    profile = normalize_web_profile(profile)
    common = [
        "-list", "/targets.txt",
        "-field-scope", "fqdn",
        "-rate-limit", str(capped_rate(policy_for(profile).httpx_rate, rate_limit)),
        "-disable-update-check",
        "-silent",
    ]
    if profile is WebScanProfile.SAFE and browser_assisted:
        profile_args = [
            "-depth", "2", "-js-crawl", "-hybrid", "-system-chrome",
            "-no-sandbox", "-xhr-extraction", "-form-extraction", "-jsonl",
            "-omit-raw", "-omit-body", "-exclude-output-fields", "raw,body",
            "-crawl-duration", "30s", "-max-domain-pages", "250",
        ]
    elif profile is WebScanProfile.SAFE:
        profile_args = [
            "-depth", "2",
            "-js-crawl",
            "-crawl-duration", "30s",
            "-max-domain-pages", "250",
        ]
    elif profile is WebScanProfile.DEEP:
        profile_args = [
            "-depth", "5",
            "-js-crawl",
            "-jsluice",
            "-knowledge-base",
            "-kb-endpoints",
            "-known-files", "all",
            "-hybrid",
            "-system-chrome",
            "-no-sandbox",
            "-xhr-extraction",
            "-form-extraction",
            "-jsonl",
            "-omit-raw",
            "-omit-body",
            "-exclude-output-fields", "raw,body",
            "-crawl-duration", "4m",
            "-max-domain-pages", "2000",
        ]
    else:
        profile_args = [
            "-depth", "5",
            "-js-crawl",
            "-jsluice",
            "-knowledge-base",
            "-kb-endpoints",
            "-known-files", "all",
            "-crawl-duration", "2m",
            "-max-domain-pages", "1000",
        ]

    structured_browser = profile is WebScanProfile.DEEP or browser_assisted
    if not structured_browser:
        common.extend(["-o", "/output/katana.txt"])

    def execute():
        return run_container(
            image=get_tool_config("katana").image,
            args=[*common[:2], *profile_args, *common[2:]],
            mounts={targets: "/targets.txt", output.parent: "/output"},
        )

    result = execute()
    # Katana 1.7 hybrid JSONL can create the -o file but emit records only to
    # stdout. Preserve that output so Deep SPA scans are not reported as empty.
    if structured_browser:
        evidence = ""
        evidence = getattr(result, "stdout", "") or ""
        sanitized = _sanitize_jsonl(evidence)
        if not sanitized:
            # Hybrid Chromium occasionally exits zero without emitting a first
            # navigation record. One isolated retry recovers the session while
            # preserving a hard failure if the target/browser remains broken.
            output.unlink(missing_ok=True)
            result = execute()
            evidence = getattr(result, "stdout", "") or ""
            sanitized = _sanitize_jsonl(evidence)
        if not sanitized:
            detail = (getattr(result, "stderr", "") or "").strip().splitlines()
            raise RuntimeError(
                "Katana Deep SPA produced no parseable JSONL output after 2 attempts"
                + (f": {detail[-1]}" if detail else "")
            )
        output.write_text(sanitized, encoding="utf-8")
