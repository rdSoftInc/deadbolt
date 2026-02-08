from pathlib import Path
import subprocess
import tempfile


def run_paramspider(targets: Path, output: Path):
    """
    paramspider – parameter discovery.

    Consumes:
      - assets (URLs only)

    Produces:
      - paths (URLs with parameters)
    """

    urls = [
        l.strip()
        for l in targets.read_text(encoding="utf-8").splitlines()
        if l.startswith("http://") or l.startswith("https://")
    ]

    if not urls:
        output.write_text("")
        return

    results = []

    for url in urls:
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{tmp}:/output",
                    "deadbolt-paramspider",
                    "-d", url,
                    "-o", "/output",
                ],
                capture_output=True,
                text=True,
            )

            if proc.returncode != 0:
                continue

            for line in proc.stdout.splitlines():
                if "=" in line:
                    results.append(line.strip())

    output.write_text("\n".join(sorted(set(results))), encoding="utf-8")