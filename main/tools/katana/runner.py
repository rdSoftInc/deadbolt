from pathlib import Path
from main.execution.docker import run_container


def run_katana(targets: Path, output: Path):
    """
    Runs Katana crawler against target list.
    Output is plain text: one discovered URL per line.
    """
    run_container(
        image="deadbolt-katana",
        args=[
            "-list", "/targets.txt",
            "-silent",
            "-o", "/output/katana.txt",
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output",
        },
    )