from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

from main.schema.normalize import Finding


def parse_gau(raw_file: Path):
    findings = {}

    with raw_file.open(encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue

            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                continue

            if url not in findings:
                findings[url] = Finding(
                    asset=url,
                    title="Historical URL",
                    tool="gau",
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
            else:
                findings[url].occurrences += 1

    return list(findings.values())