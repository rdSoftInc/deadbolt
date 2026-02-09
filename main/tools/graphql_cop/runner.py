# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief graphql-cop execution wrapper.
#
# This module defines the execution logic for graphql-cop. Unlike most tools,
# graphql-cop is executed directly per endpoint rather than via the shared
# run_container helper, due to its probing-style execution model.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
import subprocess
import tempfile


# Common GraphQL endpoint paths to probe
GRAPHQL_COMMON_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
]


def run_graphql_cop(targets: Path, output: Path):
    """
    Execute graphql-cop against candidate GraphQL endpoints.

    Consumes:
      - assets (URLs only)

    Produces:
      - paths (GraphQL endpoints and discovered operations)

    Strategy:
      - Extract base URLs from targets
      - Probe common GraphQL endpoint paths
      - Execute graphql-cop per endpoint
      - Aggregate unique results
    """

    # -------------------------------
    # Extract valid base URLs
    # -------------------------------
    urls = [
        l.strip().rstrip("/")
        for l in targets.read_text(encoding="utf-8").splitlines()
        if l.startswith("http://") or l.startswith("https://")
    ]

    if not urls:
        output.write_text("")
        return

    results = []

    # -------------------------------
    # Endpoint probing
    # -------------------------------
    for base in urls:
        for suffix in GRAPHQL_COMMON_PATHS:
            endpoint = f"{base}{suffix}"

            with tempfile.TemporaryDirectory():
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

    # -------------------------------
    # Deduplicate and persist output
    # -------------------------------
    output.write_text(
        "\n".join(sorted(set(results))),
        encoding="utf-8",
    )