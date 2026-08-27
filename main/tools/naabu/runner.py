from pathlib import Path

from main.core.tool_manifest import get_tool_config
from main.domains.web.profiles import WebScanProfile, capped_rate, normalize_web_profile
from main.execution.docker import run_container


def run_naabu(targets: Path, output: Path, *, profile: WebScanProfile | str = WebScanProfile.STANDARD, rate_limit: float | None = None):
    profile = normalize_web_profile(profile)
    port_args = {WebScanProfile.SAFE: ["-top-ports", "100"], WebScanProfile.STANDARD: ["-top-ports", "1000"], WebScanProfile.DEEP: ["-p", "-"]}[profile]
    rate = str(capped_rate(
        {WebScanProfile.SAFE: 1, WebScanProfile.STANDARD: 1000, WebScanProfile.DEEP: 750}[profile],
        rate_limit,
    ))
    run_container(
        image=get_tool_config("naabu").image,
        args=["-list", "/targets.txt", *port_args, "-scan-type", "c", "-sV-fast", "-json", "-rate", rate, "-retries", "1", "-timeout", "1500", "-disable-update-check", "-o", "/output/naabu.jsonl"],
        mounts={targets: "/targets.txt", output.parent: "/output"},
    )
