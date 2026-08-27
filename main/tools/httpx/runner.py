# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief httpx execution wrapper.
#
# This module defines the execution logic for httpx using a containerized
# runtime. httpx validates targets by probing for live HTTP services and
# produces structured JSON output for enrichment.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from main.execution.docker import run_container
from main.core.tool_manifest import get_tool_config
from main.domains.web.profiles import WebScanProfile, capped_rate, policy_for


def run_httpx(targets: Path, output: Path, *, profile: WebScanProfile | str = WebScanProfile.STANDARD, rate_limit: float | None = None):
    """
    Execute httpx against target assets or paths.

    Consumes:
      - targets (domains, URLs, or paths)

    Produces:
      - findings (newline-delimited JSON describing live HTTP services)

    Notes:
      - httpx does not perform crawling
      - It validates reachability and enriches targets with HTTP metadata
    """
    cache_dir = Path(".deadbolt/cache/httpx/dit").resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    policy = policy_for(profile)
    run_container(
        image=get_tool_config("httpx").image,
        args=[
            "-l", "/targets.txt",
            "-json",
            "-threads", str(policy.httpx_threads),
            "-rate-limit", str(capped_rate(policy.httpx_rate, rate_limit)),
            "-timeout", str(policy.httpx_timeout),
            "-o", "/output/httpx.json",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
            cache_dir: "/root/.dit",
        },
    )
