import json
from pathlib import Path
from datetime import datetime, timezone

from main.schema.normalize import Finding

def parse_httpx(raw_file: Path):
    findings = []

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            data = json.loads(line)

            url = data.get("url")
            if not url:
                continue

            findings.append(
                Finding(
                    asset=url,
                    title=data.get("title") or "Live HTTP Service",
                    tool="httpx",

                    status_code=data.get("status_code"),
                    technologies=data.get("tech") or [],
                    webserver=data.get("webserver"),
                    cdn=data.get("cdn"),
                    cdn_name=data.get("cdn_name"),

                    timestamp=datetime.now(timezone.utc),
                    evidence_path=str(raw_file),
                )
            )

    return findings

def parse_nuclei(raw_file: Path):
    SEVERITY_ORDER = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    findings = {}  # (asset, template_id) -> Finding

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            data = json.loads(line)

            asset = data.get("host") or data.get("matched") or data.get("url")
            template_id = data.get("template-id")

            if not asset or not template_id:
                continue

            title = data.get("info", {}).get("name", "Nuclei Finding")
            severity = data.get("info", {}).get("severity", "info")

            key = (asset, template_id)

            if key not in findings:
                finding = Finding(
                    asset=asset,
                    title=title,
                    tool="nuclei",
                    kind="finding", 
                    
                    severity=severity,
                    template_id=template_id,
                    timestamp=datetime.now(timezone.utc),
                    evidence_path=str(raw_file),
                )
                # dynamic attribute (allowed by pydantic)
                finding.occurrences = 1
                findings[key] = finding

            else:
                existing = findings[key]
                existing.occurrences += 1

                # keep highest severity
                if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(
                    existing.severity or "info", 0
                ):
                    existing.severity = severity
                    existing.title = title

    return list(findings.values())