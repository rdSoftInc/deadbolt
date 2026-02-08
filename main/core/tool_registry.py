from dataclasses import dataclass
from typing import Dict, Literal

AssetType = Literal["targets", "assets", "paths", "findings"]
PhaseType = Literal["discovery", "enumeration", "vulnerability"]

@dataclass(frozen=True)
class ToolSpec:
    name: str
    image: str

    phase: PhaseType
    consumes: AssetType
    produces: AssetType

    produces_severity: bool
    severity_gated: bool
    parallel: bool


"""
Deadbolt tool registry

Design rules:
- ToolSpec represents intent, not binaries
- Same binary may appear multiple times with different roles
- Names must match runtime registry keys
"""

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