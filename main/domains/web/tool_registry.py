# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file tool_registry.py
# @brief Web tool specification registry.
#
# This module defines the declarative specification for web analysis tools used
# by Deadbolt. Each ToolSpec describes the intent, execution phase, data flow,
# and orchestration constraints for a tool. The registry is consumed by the
# web runner to determine phase ordering, artifact dependencies, and execution
# behavior.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from dataclasses import dataclass
from typing import Dict, Literal

# Types describing tool input/output artifacts and execution phases
AssetType = Literal["targets", "assets", "paths", "findings"]
PhaseType = Literal["discovery", "enumeration", "vulnerability"]


@dataclass(frozen=True)
class ToolSpec:
    """
    Declarative specification for a web analysis tool.

    ToolSpec represents execution intent rather than a concrete binary.
    The same underlying tool image may appear multiple times in the registry
    with different roles, phases, or artifact transformations.
    """

    # Logical tool identifier (must match runtime registry keys)
    name: str

    # Container image used to execute the tool
    image: str

    # Execution phase used for ordering
    phase: PhaseType

    # Artifact type consumed by the tool
    consumes: AssetType

    # Artifact type produced by the tool
    produces: AssetType

    # Whether the tool produces severity-scored findings
    produces_severity: bool

    # Whether execution is gated by severity thresholds
    severity_gated: bool

    # Whether the tool may be executed in parallel
    parallel: bool


# ---------------------------------------------------------------------
# Deadbolt Web Tool Registry
#
# Design rules:
# - ToolSpec represents intent, not binaries
# - The same binary may appear multiple times with different roles
# - Tool names must match runtime registry keys
# ---------------------------------------------------------------------

TOOL_REGISTRY: Dict[str, ToolSpec] = {

    # ─────────────────────────────
    # Discovery — what exists & responds
    # ─────────────────────────────

    "subfinder": ToolSpec(
        name="subfinder",
        image="deadbolt-subfinder",
        phase="discovery",
        consumes="targets",
        produces="assets",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    "dnsx": ToolSpec(
        name="dnsx",
        image="deadbolt-dnsx",
        phase="discovery",
        consumes="assets",
        produces="assets",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    # httpx — asset validation / classification
    "httpx": ToolSpec(
        name="httpx",
        image="deadbolt-httpx",
        phase="discovery",
        consumes="assets",
        produces="assets",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    # ─────────────────────────────
    # Enumeration — surface expansion
    # ─────────────────────────────

    "gau": ToolSpec(
        name="gau",
        image="deadbolt-gau",
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    "waybackurls": ToolSpec(
        name="waybackurls",
        image="deadbolt-waybackurls",
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    "katana": ToolSpec(
        name="katana",
        image="deadbolt-katana",
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    "hakrawler": ToolSpec(
        name="hakrawler",
        image="deadbolt-hakrawler",
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    # ffuf — endpoint discovery
    "ffuf": ToolSpec(
        name="ffuf",
        image="deadbolt-ffuf",
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    # httpx — path validation / enrichment
    "httpx_paths": ToolSpec(
        name="httpx_paths",
        image="deadbolt-httpx",
        phase="enumeration",
        consumes="paths",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    # ─────────────────────────────
    # Input discovery — AppSec signal
    # ─────────────────────────────

    "paramspider": ToolSpec(
        name="paramspider",
        image="deadbolt-paramspider",
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    "graphql-cop": ToolSpec(
        name="graphql-cop",
        image="deadbolt-graphql-cop",
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    # ─────────────────────────────
    # Vulnerability — execution
    # ─────────────────────────────

    "nuclei": ToolSpec(
        name="nuclei",
        image="deadbolt-nuclei",
        phase="vulnerability",
        consumes="assets",
        produces="findings",
        produces_severity=True,
        severity_gated=True,
        parallel=True,
    ),
}