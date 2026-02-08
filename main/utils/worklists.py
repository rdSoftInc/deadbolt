# main/utils/worklists.py
from pathlib import Path
from typing import Iterable, List
from main.schema.normalize import Finding

def _write_or_merge_worklist_txt(path: Path, items: Iterable[str]) -> None:
    existing = set()
    if path.exists():
        existing = set(
            line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )

    new_items = []
    for x in items:
        x = (x or "").strip()
        if x and x not in existing:
            existing.add(x)
            new_items.append(x)

    if new_items:
        with path.open("a", encoding="utf-8") as f:
            for x in new_items:
                f.write(x + "\n")


def _findings_to_work_items(output_type: str, findings: List[Finding]) -> List[str]:
    """
    Convert normalized Finding objects into the next-stage worklist items (plain text lines).
    - assets -> domain/url in Finding.asset
    - paths  -> url/path in Finding.asset
    - findings -> not used as input list (return empty)
    """
    if output_type in ("assets", "paths"):
        return [f.asset for f in findings]
    return []