# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file generator.py
# @brief HTML report generation for Deadbolt scan runs.
#
# This module is responsible for generating the final HTML report for a
# completed Deadbolt scan. It loads normalized findings and metadata,
# applies severity gating rules, and renders the results using Jinja2
# templates.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import json
from jinja2 import Environment, FileSystemLoader, select_autoescape

from main.core.severity import severity_at_least

# Default minimum severity required for gated findings to appear in the report
DEFAULT_MIN_SEVERITY = "low"


def load_tool_registry(domain: str):
    """
    Load the tool registry for a given scan domain.

    The registry is used to determine tool-specific behavior such as
    severity gating when rendering the report.
    """
    if domain == "web":
        from main.domains.web.tool_registry import TOOL_REGISTRY
        return TOOL_REGISTRY

    if domain == "android":
        from main.domains.android.tool_registry import TOOL_REGISTRY
        return TOOL_REGISTRY

    if domain == "ios":
        from main.domains.ios.tool_registry import TOOL_REGISTRY
        return TOOL_REGISTRY

    return {}


def generate_report(run_dir: Path):
    """
    Generate the HTML report for a completed scan run.

    This function loads run metadata and normalized findings, separates
    attack surface information from vulnerability findings, applies
    severity-based filtering, and renders the final report using a Jinja2
    HTML template.
    """

    meta_path = run_dir / "meta.json"
    findings_path = run_dir / "normalized" / "findings.json"
    output_path = run_dir / "report.html"

    if not meta_path.exists():
        raise FileNotFoundError("meta.json not found")

    if not findings_path.exists():
        raise FileNotFoundError("findings.json not found")

    # Load run metadata and normalized findings
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    all_findings = json.loads(findings_path.read_text(encoding="utf-8"))

    domain = meta.get("domain", "web")
    TOOL_REGISTRY = load_tool_registry(domain)

    surface = []
    vulnerabilities = []

    # --------------------------------
    # Finding classification
    # --------------------------------
    for f in all_findings:
        kind = f.get("kind")

        # Non-vulnerability findings represent attack surface
        if kind != "finding":
            surface.append(f)
            continue

        tool = f.get("tool")
        spec = TOOL_REGISTRY.get(tool)

        # Unknown tools always pass through
        if not spec:
            vulnerabilities.append(f)
            continue

        # Tools without severity gating always pass through
        if not spec.severity_gated:
            vulnerabilities.append(f)
            continue

        # Apply severity threshold
        severity = f.get("severity") or "info"
        if severity_at_least(severity, DEFAULT_MIN_SEVERITY):
            vulnerabilities.append(f)

    # --------------------------------
    # HTML rendering
    # --------------------------------
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html"]),
    )

    template = env.get_template("report.html.j2")

    html = template.render(
        meta=meta,
        domain=domain,
        surface=surface,
        findings=vulnerabilities,
        min_severity=DEFAULT_MIN_SEVERITY,
    )

    output_path.write_text(html, encoding="utf-8")