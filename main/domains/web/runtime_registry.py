# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runtime_registry.py
# @brief Web tool runtime registry.
#
# This module defines the runtime configuration for web analysis tools.
# Each entry specifies how a tool is executed, how its output is parsed,
# and which artifacts are produced. The registry is consumed by the web
# runner to orchestrate phase-based execution and artifact flow.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from main.core.tool_runtime import ToolRuntime

# ──────────────── Discovery ────────────────

from main.tools.subfinder.runner import run_subfinder
from main.tools.subfinder.parser import parse_subfinder

from main.tools.dnsx.runner import run_dnsx
from main.tools.dnsx.parser import parse_dnsx

from main.tools.httpx.runner import run_httpx
from main.tools.httpx.parser import parse_httpx


# ──────────────── Enumeration ────────────────

from main.tools.gau.runner import run_gau
from main.tools.gau.parser import parse_gau

from main.tools.waybackurls.runner import run_waybackurls
from main.tools.waybackurls.parser import parse_waybackurls

from main.tools.katana.runner import run_katana
from main.tools.katana.parser import parse_katana

from main.tools.hakrawler.runner import run_hakrawler
from main.tools.hakrawler.parser import parse_hakrawler

from main.tools.ffuf.runner import run_ffuf
from main.tools.ffuf.parser import parse_ffuf

from main.tools.paramspider.runner import run_paramspider
from main.tools.paramspider.parser import parse_paramspider

from main.tools.graphql_cop.runner import run_graphql_cop
from main.tools.graphql_cop.parser import parse_graphql_cop


# ──────────────── Vulnerability ────────────────

from main.tools.nuclei.runner import run_nuclei
from main.tools.nuclei.parser import parse_nuclei


# ──────────────── Helpers ────────────────

def _mark_paths(findings):
    """
    Mark parsed HTTP findings as path artifacts.

    This helper is used by enrichment tools to reclassify findings so they
    can be consumed correctly by downstream phases.
    """
    for f in findings:
        f.kind = "path"


# ──────────────── Runtime Registry ────────────────

# Declarative mapping of web tools to their runtime definitions
TOOL_RUNTIMES = {

    # ---------------- Discovery ----------------

    "subfinder": ToolRuntime(
        runner=run_subfinder,
        parser=parse_subfinder,
        output_name="subfinder.txt",
    ),

    "dnsx": ToolRuntime(
        runner=run_dnsx,
        parser=parse_dnsx,
        output_name="dnsx.txt",
    ),

    "httpx": ToolRuntime(
        runner=run_httpx,
        parser=parse_httpx,
        output_name="httpx.json",
    ),

    # ---------------- Enumeration ----------------

    "gau": ToolRuntime(
        runner=run_gau,
        parser=parse_gau,
        output_name="gau.txt",
    ),

    "waybackurls": ToolRuntime(
        runner=run_waybackurls,
        parser=parse_waybackurls,
        output_name="waybackurls.txt",
    ),

    "katana": ToolRuntime(
        runner=run_katana,
        parser=parse_katana,
        output_name="katana.txt",
    ),

    "hakrawler": ToolRuntime(
        runner=run_hakrawler,
        parser=parse_hakrawler,
        output_name="hakrawler.txt",
    ),

    "ffuf": ToolRuntime(
        runner=run_ffuf,
        parser=parse_ffuf,
        output_name="ffuf.json",
    ),

    "paramspider": ToolRuntime(
        runner=run_paramspider,
        parser=parse_paramspider,
        output_name="paramspider.txt",
    ),

    "graphql-cop": ToolRuntime(
        runner=run_graphql_cop,
        parser=parse_graphql_cop,
        output_name="graphql_cop.txt",
    ),

    # ---------------- Enrichment ----------------

    "httpx_paths": ToolRuntime(
        runner=run_httpx,
        parser=parse_httpx,
        output_name="httpx.json",
        postprocess=_mark_paths,
        raw_subdir="httpx_paths",
    ),

    # ---------------- Vulnerability ----------------

    "nuclei": ToolRuntime(
        runner=run_nuclei,
        parser=parse_nuclei,
        output_name="nuclei.jsonl",
    ),
}