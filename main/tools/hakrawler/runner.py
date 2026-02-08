from pathlib import Path
import subprocess


def run_hakrawler(targets: Path, output: Path):
    """
    hakrawler – client-side crawling.

    Consumes:
      - assets (URLs only)

    Produces:
      - paths
    """

    # Filter only URLs (hakrawler requires scheme)
    urls = []
    for line in targets.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)

    if not urls:
        # Nothing to crawl → clean skip
        output.write_text("")
        return

    proc = subprocess.run(
        ["docker", "run", "--rm", "-i", "deadbolt-hakrawler"],
        input="\n".join(urls),
        text=True,
        capture_output=True,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"hakrawler failed\nSTDERR:\n{proc.stderr}"
        )

    output.write_text(proc.stdout, encoding="utf-8")