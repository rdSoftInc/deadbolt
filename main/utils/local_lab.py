"""Safe normalization for Docker-hosted local web assessment targets."""

from dataclasses import dataclass
import socket
import subprocess
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from main.core.tool_manifest import get_tool_config


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
DOCKER_HOST = "host.docker.internal"


@dataclass(frozen=True)
class LocalLabTarget:
    original: str
    canonical: str
    transport: str


class LocalLabPreflightError(RuntimeError):
    """Raised when a loopback lab is unavailable to the host or Docker."""


def normalize_local_lab_target(value: str) -> LocalLabTarget:
    """Validate one loopback HTTP URL and map it to the Docker host gateway."""

    original = value.strip()
    parsed = urlsplit(original)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("local-lab targets must use http:// or https://")
    if not parsed.hostname or parsed.hostname.lower() not in LOCAL_HOSTS:
        raise ValueError("local-lab targets must use localhost or a loopback IP")
    if parsed.username or parsed.password:
        raise ValueError("credentials are not permitted in local-lab target URLs")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("local-lab target has an invalid port") from exc
    host = parsed.hostname.lower()
    canonical_host = f"[{host}]" if ":" in host else host
    transport_host = DOCKER_HOST
    if port is not None:
        canonical_host = f"{canonical_host}:{port}"
        transport_host = f"{transport_host}:{port}"
    path = parsed.path or "/"
    canonical = urlunsplit((parsed.scheme, canonical_host, path, parsed.query, ""))
    transport = urlunsplit((parsed.scheme, transport_host, path, parsed.query, ""))
    return LocalLabTarget(original, canonical, transport)


def normalize_local_lab_targets(values: list[str]) -> list[LocalLabTarget]:
    """Normalize, deduplicate, and validate a local-lab target collection."""

    normalized = []
    seen = set()
    for value in values:
        target = normalize_local_lab_target(value)
        if target.canonical not in seen:
            seen.add(target.canonical)
            normalized.append(target)
    if not normalized:
        raise ValueError("local-lab target file contains no usable URLs")
    return normalized


def preflight_local_lab_targets(
    targets: list[LocalLabTarget],
    *,
    timeout: float = 5.0,
    command_runner: Callable = subprocess.run,
) -> None:
    """Verify each local lab TCP service from macOS and Docker networking."""

    failures = []
    image = get_tool_config("httpx").image
    for target in targets:
        canonical = urlsplit(target.canonical)
        transport = urlsplit(target.transport)
        port = canonical.port or (443 if canonical.scheme == "https" else 80)
        try:
            with socket.create_connection((canonical.hostname or "localhost", port), timeout):
                pass
        except OSError as exc:
            failures.append(
                f"{target.canonical} is not reachable from the host ({exc})"
            )
            continue

        result = command_runner(
            [
                "docker", "run", "--rm", "--entrypoint", "/bin/sh", image,
                "-c", 'nc -z -w "$3" "$1" "$2"', "deadbolt-preflight",
                transport.hostname or DOCKER_HOST, str(port), str(max(1, int(timeout))),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            suffix = f" ({detail})" if detail else ""
            failures.append(
                f"{target.transport} is not reachable from Docker{suffix}"
            )

    if failures:
        raise LocalLabPreflightError(
            "Local lab preflight failed before scanners started:\n- "
            + "\n- ".join(failures)
            + "\nConfirm the lab publishes its port, for example: "
            "docker run --rm -d -p 3000:3000 bkimminich/juice-shop"
        )
