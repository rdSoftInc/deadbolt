from pathlib import Path
from datetime import datetime, timezone

from main.schema.normalize import Finding


def parse_dnsx(raw_file: Path):
    findings = {}

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            domain = line.strip()
            if not domain:
                continue

            if domain not in findings:
                findings[domain] = Finding(
                    asset=domain,
                    title="Resolvable domain",
                    tool="dnsx",
                    kind="asset",

                    status_code=None,
                    technologies=[],
                    webserver=None,
                    cdn=None,
                    cdn_name=None,

                    severity=None,
                    template_id=None,
                    occurrences=1,

                    timestamp=datetime.now(timezone.utc),
                    evidence_path=str(raw_file),
                )
            else:
                findings[domain].occurrences += 1

    return list(findings.values())