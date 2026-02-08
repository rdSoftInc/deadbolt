from pathlib import Path
from datetime import datetime, timezone
from typing import List

from main.schema.normalize import Finding


def parse_graphql_cop(raw_file: Path) -> List[Finding]:
    findings = {}
    timestamp = datetime.now(timezone.utc)

    for line in raw_file.read_text(encoding="utf-8").splitlines():
        if "::" not in line:
            continue

        endpoint, detail = line.split("::", 1)
        endpoint = endpoint.strip()
        detail = detail.strip()

        key = f"{endpoint}:{detail}"

        if key not in findings:
            findings[key] = Finding(
                asset=endpoint,
                title=f"GraphQL exposure: {detail}",
                tool="graphql-cop",
                kind="path",

                status_code=None,
                technologies=["graphql"],
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
            findings[key].occurrences += 1

    return list(findings.values())