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

from main.core.tool_manifest import get_tool_config

# Types describing tool input/output artifacts and execution phases
AssetType = Literal["targets", "assets", "paths", "scan_targets", "findings"]
PhaseType = Literal["discovery", "enumeration", "vulnerability"]
ToolCategory = Literal["discover", "validate", "enumerate", "test"]

TOOL_CATEGORIES: Dict[str, ToolCategory] = {
    "subfinder": "discover", "dnsx": "discover", "naabu": "discover", "tlsx": "discover",
    "httpx": "validate", "httpx_paths": "validate",
    "gau": "enumerate", "waybackurls": "enumerate", "katana": "enumerate",
    "hakrawler": "enumerate", "ffuf": "enumerate", "linkfinder": "enumerate",
    "paramspider": "enumerate", "graphql-cop": "enumerate", "arjun": "enumerate",
    "nuclei": "test",
}


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

    @property
    def category(self) -> ToolCategory:
        """User-facing lifecycle category for this logical tool role."""

        return TOOL_CATEGORIES[self.name]


# ---------------------------------------------------------------------
# Deadbolt Web Tool Registry
#
# Design rules:
# - ToolSpec represents intent, not binaries
# - The same binary may appear multiple times with different roles
# - Tool names must match runtime registry keys
# - Enumeration tools produce isolated paths merged before httpx_paths
# - Nuclei consumes the union of live roots and validated in-scope paths
# ---------------------------------------------------------------------

TOOL_REGISTRY: Dict[str, ToolSpec] = {

    # ─────────────────────────────
    # Discovery — what exists & responds
    # ─────────────────────────────

    "subfinder": ToolSpec(
        name="subfinder",
        image=get_tool_config("subfinder").image,
        phase="discovery",
        consumes="targets",
        produces="assets",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    "dnsx": ToolSpec(
        name="dnsx",
        image=get_tool_config("dnsx").image,
        phase="discovery",
        consumes="assets",
        produces="assets",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    "naabu": ToolSpec(
        name="naabu",
        image=get_tool_config("naabu").image,
        phase="discovery",
        consumes="assets",
        produces="assets",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    "tlsx": ToolSpec(name="tlsx", image=get_tool_config("tlsx").image, phase="discovery", consumes="assets", produces="assets", produces_severity=False, severity_gated=False, parallel=True),

    # httpx — asset validation / classification
    "httpx": ToolSpec(
        name="httpx",
        image=get_tool_config("httpx").image,
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
        image=get_tool_config("gau").image,
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    "waybackurls": ToolSpec(
        name="waybackurls",
        image=get_tool_config("waybackurls").image,
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    "katana": ToolSpec(
        name="katana",
        image=get_tool_config("katana").image,
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    "hakrawler": ToolSpec(
        name="hakrawler",
        image=get_tool_config("hakrawler").image,
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    # ffuf — endpoint discovery
    "ffuf": ToolSpec(
        name="ffuf",
        image=get_tool_config("ffuf").image,
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    "linkfinder": ToolSpec(
        name="linkfinder",
        image=get_tool_config("linkfinder").image,
        phase="enumeration",
        consumes="paths",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    # httpx — path validation / enrichment
    "httpx_paths": ToolSpec(
        name="httpx_paths",
        image=get_tool_config("httpx").image,
        phase="enumeration",
        consumes="paths",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=False,
    ),

    # ─────────────────────────────
    # Input discovery — AppSec signal
    # ─────────────────────────────

    "paramspider": ToolSpec(
        name="paramspider",
        image=get_tool_config("paramspider").image,
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    "graphql-cop": ToolSpec(
        name="graphql-cop",
        image=get_tool_config("graphql-cop").image,
        phase="enumeration",
        consumes="assets",
        produces="paths",
        produces_severity=False,
        severity_gated=False,
        parallel=True,
    ),

    "arjun": ToolSpec(name="arjun", image=get_tool_config("arjun").image, phase="enumeration", consumes="assets", produces="paths", produces_severity=False, severity_gated=False, parallel=True),

    # ─────────────────────────────
    # Vulnerability — execution
    # ─────────────────────────────

    "nuclei": ToolSpec(
        name="nuclei",
        image=get_tool_config("nuclei").image,
        phase="vulnerability",
        consumes="scan_targets",
        produces="findings",
        produces_severity=True,
        severity_gated=True,
        parallel=False,
    ),
}
