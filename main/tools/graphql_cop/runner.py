from pathlib import Path
import subprocess
import tempfile


GRAPHQL_COMMON_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
]


def run_graphql_cop(targets: Path, output: Path):
    """
    graphql-cop – GraphQL endpoint analysis.

    Consumes:
      - assets (URLs only)

    Produces:
      - paths (GraphQL endpoints & discovered operations)
    """

    urls = [
        l.strip().rstrip("/")
        for l in targets.read_text(encoding="utf-8").splitlines()
        if l.startswith("http://") or l.startswith("https://")
    ]

    if not urls:
        output.write_text("")
        return

    results = []

    for base in urls:
        for suffix in GRAPHQL_COMMON_PATHS:
            endpoint = f"{base}{suffix}"

            with tempfile.TemporaryDirectory() as tmp:
                proc = subprocess.run(
                    [
                        "docker", "run", "--rm",
                        "deadbolt-graphql-cop",
                        "-t", endpoint,
                        "--quiet",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if proc.returncode != 0:
                    continue

                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if line:
                        results.append(f"{endpoint} :: {line}")

    output.write_text("\n".join(sorted(set(results))), encoding="utf-8")