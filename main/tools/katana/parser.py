from pathlib import Path
from datetime import datetime, timezone

from main.schema.normalize import Finding


def parse_katana(raw_file: Path):
    findings = {}
    # key = asset URL, value = Finding

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue

            if url not in findings:
                finding = Finding(
                    asset=url,
                    title="Discovered URL",
                    tool="katana",
                    kind="path",

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
                findings[url] = finding
            else:
                findings[url].occurrences += 1

    return list(findings.values())