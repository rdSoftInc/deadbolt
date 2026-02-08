import subprocess
from pathlib import Path
from typing import Dict, List, Optional

def run_container(
    *,
    image: str,
    args: List[str],
    mounts: Dict[Path, str],
    entrypoint: Optional[str] = None,
):
    if not mounts:
        raise ValueError("run_container() requires at least one volume mount")

    cmd = ["docker", "run", "--rm"]

    for host, container in mounts.items():
        cmd += ["-v", f"{host.resolve()}:{container}"]

    if entrypoint:
        cmd += ["--entrypoint", entrypoint]

    cmd.append(image)
    cmd.extend(args)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Docker failed\nSTDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}"
        )