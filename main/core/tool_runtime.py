from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional
from main.schema.normalize import Finding

@dataclass(frozen=True)
class ToolRuntime:
    runner: Callable[[Path, Path], None]
    parser: Callable[[Path], List[Finding]]
    output_name: str          # e.g. "httpx.json"
    postprocess: Callable[[List[Finding]], None] | None = None
    raw_subdir: Optional[str] = None  