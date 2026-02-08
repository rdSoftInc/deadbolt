from pathlib import Path
from main.execution.docker import run_container

def run_httpx(targets: Path, output: Path):
    run_container(
        image="deadbolt-httpx",
        args=[
            "-l", "/targets.txt",
            "-json",
            "-o", "/output/httpx.json"
        ],
        mounts={
            targets: "/targets.txt",
            output.parent: "/output"
        }
    )