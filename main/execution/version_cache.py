from pathlib import Path
from datetime import datetime, timezone
import json

CACHE_DIR = Path.home() / ".deadbolt"
CACHE_FILE = CACHE_DIR / "version_cache.json"
DEFAULT_TTL = 3600  # 1 hour


def load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {"schema": 1, "ttl_seconds": DEFAULT_TTL, "tools": {}}
    return json.loads(CACHE_FILE.read_text(encoding="utf-8"))


def save_cache(cache: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def is_fresh(entry: dict, ttl: int) -> bool:
    try:
        ts = datetime.fromisoformat(entry["checked_at"])
    except Exception:
        return False
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return age < ttl

def get_cached_versions(
    *,
    image: str,
    resolve_installed,
    resolve_latest,
) -> tuple[str, str]:
    cache = load_cache()
    ttl = cache.get("ttl_seconds", DEFAULT_TTL)
    tools = cache.setdefault("tools", {})

    entry = tools.get(image)

    if entry and is_fresh(entry, ttl):
        return entry["installed"], entry["latest"]

    installed = resolve_installed(image)
    latest = resolve_latest(image)

    tools[image] = {
        "installed": installed,
        "latest": latest,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    save_cache(cache)
    return installed, latest