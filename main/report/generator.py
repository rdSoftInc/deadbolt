from pathlib import Path
import json
from jinja2 import Environment, FileSystemLoader, select_autoescape

from main.core.severity import severity_at_least
from main.core.tool_registry import TOOL_REGISTRY

DEFAULT_MIN_SEVERITY = "medium"


def generate_report(run_dir: Path):
    meta_path = run_dir / "meta.json"
    findings_path = run_dir / "normalized" / "findings.json"
    output_path = run_dir / "report.html"

    if not meta_path.exists():
        raise FileNotFoundError("meta.json not found")
    if not findings_path.exists():
        raise FileNotFoundError("findings.json not found")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    all_findings = json.loads(findings_path.read_text(encoding="utf-8"))

    surface = []
    vulnerabilities = []

    for f in all_findings:
        kind = f.get("kind")

        # Anything that is not an actual vuln is attack surface
        if kind != "finding":
            surface.append(f)
            continue

        tool = f.get("tool")
        spec = TOOL_REGISTRY.get(tool)

        # Unknown tools: always show
        if not spec:
            vulnerabilities.append(f)
            continue

        # Non-gated tools always pass
        if not spec.severity_gated:
            vulnerabilities.append(f)
            continue

        severity = f.get("severity") or "info"
        if severity_at_least(severity, DEFAULT_MIN_SEVERITY):
            vulnerabilities.append(f)

    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html"]),
    )

    template = env.get_template("report.html.j2")

    html = template.render(
        meta=meta,
        surface=surface,
        findings=vulnerabilities,
        min_severity=DEFAULT_MIN_SEVERITY,
    )

    output_path.write_text(html, encoding="utf-8")