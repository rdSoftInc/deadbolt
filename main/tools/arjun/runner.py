from pathlib import Path
from main.core.tool_manifest import get_tool_config
from main.domains.web.profiles import WebScanProfile, normalize_web_profile
from main.execution.docker import run_container


def run_arjun(targets: Path, output: Path, *, profile: WebScanProfile | str = WebScanProfile.STANDARD, rate_limit: float | None = None):
    profile = normalize_web_profile(profile)
    threads = {WebScanProfile.SAFE: "1", WebScanProfile.STANDARD: "10", WebScanProfile.DEEP: "15"}[profile]
    if rate_limit is not None:
        threads = str(max(1, min(int(threads), int(rate_limit))))
    run_container(image=get_tool_config("arjun").image, args=["-i", "/targets.txt", "-oJ", "/output/arjun.json", "-t", threads, "--stable"], mounts={targets: "/targets.txt", output.parent: "/output"})

    # Arjun exits successfully without creating its JSON file when no
    # parameters are discovered. Preserve the pipeline's artifact contract:
    # a successful empty scan is valid evidence, not an execution failure.
    if not output.exists():
        output.write_text("{}\n", encoding="utf-8")
