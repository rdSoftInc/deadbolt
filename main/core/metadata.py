from datetime import datetime, timezone
from pathlib import Path
import json
from typing import Dict, Optional

def write_metadata(
    *,
    base_dir: Path,
    run_id: str,
    targets_file: Path,
    tools: Dict[str, Dict[str, str]],
    started_at: datetime,
    finished_at: datetime,
    deadbolt_version: str = "0.1.0",
    errors: Optional[Dict[str, str]] = None,
):
    meta = {
        "run_id": run_id,
        "started_at": started_at.astimezone(timezone.utc).isoformat(),
        "finished_at": finished_at.astimezone(timezone.utc).isoformat(),
        "targets_file": str(targets_file),
        "deadbolt_version": deadbolt_version,
        "tools": tools,
        "errors": errors or {},
    }

    meta_path = base_dir / "meta.json"
    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)