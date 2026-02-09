# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file tool_registry.py
# @brief iOS tool specification registry.
#
# This module defines the declarative specification for iOS analysis tools.
# Each tool specification describes execution metadata such as phase ordering,
# container image, data flow, and execution constraints. The registry is
# consumed by the iOS runner to determine orchestration behavior.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from dataclasses import dataclass
from typing import Dict, Literal

# Types describing tool input/output and execution phases
AssetType = Literal["ipa", "assets", "findings"]
PhaseType = Literal["static", "analysis"]


@dataclass(frozen=True)
class ToolSpec:
    """
    Declarative specification for an iOS analysis tool.

    This dataclass defines execution metadata used by the orchestration layer
    to determine ordering, data dependencies, and execution constraints.
    """

    # Logical tool identifier
    name: str

    # Container image used to execute the tool
    image: str

    # Execution phase used for ordering
    phase: PhaseType

    # Asset type consumed by the tool
    consumes: AssetType

    # Asset type produced by the tool
    produces: AssetType

    # Whether the tool produces severity-scored findings
    produces_severity: bool

    # Whether execution is gated by severity thresholds
    severity_gated: bool

    # Whether the tool may be executed in parallel
    parallel: bool


# Declarative registry of iOS analysis tools
TOOL_REGISTRY: Dict[str, ToolSpec] = {

    "mobsf": ToolSpec(
        name="mobsf",
        image="opensecurity/mobile-security-framework-mobsf",
        phase="analysis",
        consumes="ipa",
        produces="findings",
        produces_severity=True,
        severity_gated=False,
        parallel=False,
    ),

}