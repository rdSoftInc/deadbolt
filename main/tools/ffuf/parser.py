import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List

from main.schema.normalize import Finding


def parse_ffuf(raw_file: Path) -> List[Finding]:
    findings = {}
    timestamp = datetime.now(timezone.utc)

    data = json.loads(raw_file.read_text(encoding="utf-8"))

    for r in data.get("results", []):
        url = r.get("url")
        if not url:
            continue

        if url not in findings:
            findings[url] = Finding(
                asset=url,
                title="Discovered endpoint (ffuf)",
                tool="ffuf",
                kind="path",

                status_code=r.get("status"),
                technologies=[],
                webserver=None,
                cdn=None,
                cdn_name=None,

                severity=None,
                template_id=None,
                occurrences=1,

                timestamp=timestamp,
                evidence_path=str(raw_file),
            )
        else:
            findings[url].occurrences += 1

    return list(findings.values())