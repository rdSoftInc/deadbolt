from pathlib import Path
from main.execution.docker import run_container


def run_ffuf(targets: Path, output: Path):
    """
    ffuf endpoint discovery.

    Consumes:
      - assets (domains / URLs)

    Produces:
      - paths (JSON output)

    Strategy:
      - host × path fuzzing
      - no recursion
      - deterministic wordlist
    """
    normalized = output.parent / "ffuf_targets.txt"

    lines = targets.read_text().splitlines()
    hosts = []

    for l in lines:
        l = l.strip()
        if not l:
            continue
        if l.startswith("http://") or l.startswith("https://"):
            l = l.split("://", 1)[1]
        hosts.append(l)

    normalized.write_text("\n".join(hosts))

    wordlist = Path("wordlists/common.txt")
    if not wordlist.is_file():
      raise RuntimeError(
          "wordlists/common.txt must exist and be a file (ffuf wordlist missing)"
      )

    run_container(
        image="deadbolt-ffuf",
        args=[
            "-w", "/wordlists/common.txt",
            "-u", "https://FUZZ",
            "-mc", "200,204,301,302,307,401,403",
            "-of", "json",
            "-o", "/output/ffuf.json",
            "-timeout", "10",
            "-t", "20",
            "-sa",
            "-s",
        ],
        mounts={
            normalized: "/targets.txt",
            output.parent: "/output",
            Path("wordlists/common.txt"): "/wordlists/common.txt",
        },
    )