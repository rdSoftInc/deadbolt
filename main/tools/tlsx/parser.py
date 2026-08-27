from datetime import datetime, timezone
import json
from pathlib import Path
from main.schema.normalize import Finding


def parse_tlsx(raw_file: Path) -> list[Finding]:
    result = []
    for line in raw_file.read_text(encoding="utf-8").splitlines():
        try: item = json.loads(line)
        except json.JSONDecodeError: continue
        host = str(item.get("host") or item.get("input") or "")
        if not host: continue
        result.append(Finding(asset=host, title=f"TLS service: {host}", tool="tlsx", kind="asset", severity="low", timestamp=datetime.now(timezone.utc), evidence_path=str(raw_file), metadata={k: item.get(k) for k in ("subject_cn", "issuer_cn", "not_before", "not_after", "tls_version", "cipher", "san", "jarm_hash") if item.get(k) is not None}))
    return result
