from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit
from main.schema.normalize import Finding


def parse_arjun(raw_file: Path) -> list[Finding]:
    try: payload=json.loads(raw_file.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError): return []
    findings=[]
    for endpoint, params in payload.items() if isinstance(payload, dict) else []:
        if not isinstance(params, list): continue
        parsed=urlsplit(endpoint)
        url=urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode([(str(p), '') for p in sorted(set(params))]), ''))
        findings.append(Finding(asset=url, title=f"Parameters discovered: {parsed.path}", tool='arjun', kind='path', severity='low', timestamp=datetime.now(timezone.utc), evidence_path=str(raw_file), metadata={'parameters': sorted(set(params)), 'active_probe': True}))
    return findings
