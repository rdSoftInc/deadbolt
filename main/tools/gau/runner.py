from pathlib import Path
from main.execution.docker import run_container


def run_gau(targets: Path, output: Path):
    """
    Runs gau against target domains.
    Output: one URL per line.
    """
    run_container(
        image="deadbolt-gau",
        args=[
            "--providers", "wayback,commoncrawl,otx",
            "--subs",
            "--o", "/output/gau.txt",
            "/targets.txt",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )