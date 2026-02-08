from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional

class Finding(BaseModel):
    asset: str
    title: str
    tool: str

    kind: str  # asset | path | finding

    status_code: Optional[int] = None
    technologies: List[str] = Field(default_factory=list)
    webserver: Optional[str] = None
    cdn: Optional[bool] = None
    cdn_name: Optional[str] = None

    severity: Optional[str] = None
    template_id: Optional[str] = None

    occurrences: int = 1

    timestamp: datetime
    evidence_path: str