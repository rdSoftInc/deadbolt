from pathlib import Path
from main.execution.docker import run_container


def run_dnsx(targets: Path, output: Path):
    """
    Runs dnsx to resolve domains.
    Output: one resolvable domain per line.
    """
    run_container(
        image="deadbolt-dnsx",
        args=[
            "-l", "/targets.txt",
            "-silent",
            "-o", "/output/dnsx.txt",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )