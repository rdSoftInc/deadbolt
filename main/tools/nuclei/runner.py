from pathlib import Path
from main.execution.docker import run_container


def run_nuclei(targets: Path, output: Path, min_severity: str = "medium"):
    run_container(
        image="deadbolt-nuclei",
        args=[
            "-l", "/targets.txt",
            "-jsonl",
            "-severity", min_severity,
            "-o", "/output/nuclei.jsonl",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )