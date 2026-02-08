# main/utils/resume.py
from pathlib import Path
from datetime import datetime


def _resolve_run_base(resume_from: Path | None) -> Path:
    """
    Resolve the run base directory.

    Fresh run:
        outputs/run_YYYYMMDD_HHMMSS

    Resume run:
        outputs/run_xxx/
    """
    if resume_from is None:
        run_id = datetime.now().strftime("run_%Y%m%d_%H%M%S")
        return (Path("outputs") / run_id).resolve()

    resume_from = resume_from.resolve()

    # Directory-only resume semantics
    if (
        resume_from.is_dir()
        and resume_from.name.startswith("run_")
        and resume_from.parent.name == "outputs"
    ):
        return resume_from

    raise RuntimeError(
        "Resume path must be an outputs/run_xxx/ directory"
    )