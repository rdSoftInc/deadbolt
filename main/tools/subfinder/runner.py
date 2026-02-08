from pathlib import Path
from main.execution.docker import run_container


def run_subfinder(targets: Path, output: Path):
    """
    Runs subfinder against target domains.
    Output: one subdomain per line.
    """
    run_container(
        image="deadbolt-subfinder",
        args=[
            "-dL", "/targets.txt",
            "-silent",
            "-o", "/output/subfinder.txt",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )