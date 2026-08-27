from pathlib import Path
from main.core.tool_manifest import get_tool_config
from main.execution.docker import run_container


def run_tlsx(targets: Path, output: Path):
    run_container(image=get_tool_config("tlsx").image, args=["-l", "/targets.txt", "-json", "-silent", "-san", "-cn", "-so", "-version", "-cipher", "-jarm", "-timeout", "5", "-o", "/output/tlsx.jsonl"], mounts={targets: "/targets.txt", output.parent: "/output"})
