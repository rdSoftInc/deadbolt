from datetime import datetime, timezone
import json
from pathlib import Path

from main.schema.normalize import Finding


def parse_naabu(raw_file: Path) -> list[Finding]:
    findings = {}
    timestamp = datetime.now(timezone.utc)
    for line in raw_file.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(item.get("host") or item.get("ip") or "").strip()
        port = item.get("port")
        if not host or not isinstance(port, int):
            continue
        asset = f"{host}:{port}"
        findings[asset] = Finding(asset=asset, title=f"Open port discovered: {asset}", tool="naabu", kind="asset", severity="low", timestamp=timestamp, evidence_path=str(raw_file), metadata={"host": host, "ip": item.get("ip"), "port": port, "protocol": item.get("protocol", "tcp"), "service": item.get("service") or item.get("service_name"), "tls": item.get("tls", False)})
    return [findings[key] for key in sorted(findings)]
