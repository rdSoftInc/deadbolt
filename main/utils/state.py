import json
import hashlib
from pathlib import Path

def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def load_state(path: Path) -> dict:
    if not path.exists():
        return {"schema": 1, "tools": {}}
    return json.loads(path.read_text(encoding="utf-8"))

def save_state(path: Path, state: dict) -> None:
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")