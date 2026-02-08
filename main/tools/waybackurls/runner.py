from pathlib import Path
from urllib.parse import urlparse
from main.execution.docker import run_container


def _normalize_domains(input_file: Path) -> Path:
    """
    Extract bare domains from a mixed asset list.
    """
    domains = set()

    with input_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            if "://" in line:
                parsed = urlparse(line)
                host = parsed.hostname
            else:
                host = line

            if host:
                domains.add(host.lower())

    out = input_file.parent / "wayback_domains.txt"
    out.write_text("\n".join(sorted(domains)) + "\n", encoding="utf-8")
    return out


def run_waybackurls(targets: Path, output: Path):
    """
    waybackurls – historical URL discovery.

    Consumes:
      - assets (mixed domains + URLs)

    Produces:
      - paths (historical endpoints)
    """
    domains_file = _normalize_domains(targets)

    run_container(
        image="deadbolt-waybackurls",
        entrypoint="sh",
        args=[
            "-c",
            f"cat /input/domains.txt | waybackurls > /output/{output.name}"
        ],
        mounts={
            domains_file: "/input/domains.txt",
            output.parent: "/output",
        },
    )