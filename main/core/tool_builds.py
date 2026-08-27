"""Manifest-driven Docker builds and pulls for Deadbolt scanners."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
import time
from typing import Callable, Iterable

from main.core.tool_diagnostics import (
    CommandResult,
    ToolStatus,
    collect_tool_statuses,
    docker_daemon_available,
    run_command,
)
from main.core.tool_manifest import ToolConfig, load_tool_manifest
from main.execution.version import get_tool_version


PROJECT_ROOT = Path(__file__).parents[2]
BuildRunner = Callable[[list[str], float], CommandResult]
ProgressCallback = Callable[[str, str, str | None], None]


@dataclass(frozen=True)
class ToolBuildResult:
    name: str
    action: str
    image: str
    expected: str
    tags: list[str]
    status: str
    installed: str | None
    verified: bool
    duration_seconds: float
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def select_tools(
    *,
    names: Iterable[str] = (),
    domains: Iterable[str] = (),
    statuses: list[ToolStatus] | None = None,
    outdated: bool = False,
) -> list[ToolConfig]:
    """Select tools in manifest order, with filters combined as an intersection."""

    manifest = load_tool_manifest()
    requested_names = set(names)
    requested_domains = set(domains)
    unknown_names = requested_names - manifest.tools.keys()
    if unknown_names:
        raise ValueError("unknown tool(s): " + ", ".join(sorted(unknown_names)))
    unknown_domains = requested_domains - {"web", "network", "android", "ios"}
    if unknown_domains:
        raise ValueError("unknown domain(s): " + ", ".join(sorted(unknown_domains)))

    drifted = None
    if outdated:
        if statuses is None:
            raise ValueError("outdated selection requires local tool statuses")
        repairable = {"missing", "rebuild_required", "unverifiable"}
        drifted = {item.name for item in statuses if item.status in repairable}

    selected = []
    for config in manifest.tools.values():
        if requested_names and config.name not in requested_names:
            continue
        if requested_domains and not requested_domains.intersection(config.domains):
            continue
        if drifted is not None and config.name not in drifted:
            continue
        selected.append(config)
    return selected


def build_command(
    config: ToolConfig,
    *,
    project_root: Path = PROJECT_ROOT,
    no_cache: bool = False,
    pull: bool = False,
    image_tags: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Create the Docker command and resulting aliases for one tool."""

    if not config.managed:
        return ["docker", "pull", config.image], [config.image]

    dockerfile = project_root / str(config.dockerfile)
    tags = image_tags or [config.image, config.versioned_image, config.current_image]
    command = ["docker", "build"]
    if no_cache:
        command.append("--no-cache")
    if pull:
        command.append("--pull")
    command.extend(["--build-arg", f"{config.build_arg}={config.version}"])
    command.extend(["--label", "io.deadbolt.managed=true"])
    command.extend(["--label", f"io.deadbolt.tool={config.name}"])
    command.extend(["--label", f"io.deadbolt.version={config.display_version}"])
    for tag in tags:
        command.extend(["--tag", tag])
    command.extend(["--file", str(dockerfile), str(dockerfile.parent)])
    return command, tags


def _tail_error(result: CommandResult) -> str:
    output = (result.stderr or result.stdout).strip()
    if not output:
        return f"Docker exited with code {result.returncode}"
    lines = output.splitlines()
    decisive = [
        line for line in lines
        if "requires go >=" in line.lower()
        or "no matching versions" in line.lower()
        or "error:" in line.lower()
    ]
    combined = []
    for line in [*decisive[-3:], *lines[-8:]]:
        if line not in combined:
            combined.append(line)
    return "\n".join(combined)


def build_tool(
    config: ToolConfig,
    *,
    project_root: Path = PROJECT_ROOT,
    no_cache: bool = False,
    pull: bool = False,
    image_tags: list[str] | None = None,
    command_runner: BuildRunner = run_command,
    installed_resolver: Callable[[str], str] = get_tool_version,
) -> ToolBuildResult:
    """Build or pull one scanner, then verify the runtime image version."""

    action = "build" if config.managed else "pull"
    command, tags = build_command(
        config,
        project_root=project_root,
        no_cache=no_cache,
        pull=pull,
        image_tags=image_tags,
    )
    started = time.monotonic()
    result = command_runner(command, 3600)
    duration = round(time.monotonic() - started, 2)
    if result.returncode != 0:
        return ToolBuildResult(
            config.name, action, config.image, config.display_version, tags,
            "failed", None, False, duration, _tail_error(result)
        )

    get_tool_version.cache_clear()
    installed = installed_resolver(config.image)
    verified = installed not in {None, "unknown"} and installed.lstrip("v") == config.display_version
    if not verified:
        detail = f"version verification failed: installed {installed}, expected {config.display_version}"
        status = "failed"
    else:
        detail = f"{action} complete; version {installed} verified"
        status = "success"
    return ToolBuildResult(
        config.name, action, config.image, config.display_version, tags,
        status, installed, verified, duration, detail
    )


def build_tools(
    configs: list[ToolConfig],
    *,
    workers: int = 1,
    project_root: Path = PROJECT_ROOT,
    no_cache: bool = False,
    pull: bool = False,
    command_runner: BuildRunner = run_command,
    installed_resolver: Callable[[str], str] = get_tool_version,
    progress_callback: ProgressCallback | None = None,
) -> list[ToolBuildResult]:
    """Build selected tools concurrently while preserving manifest order."""

    def execute(config: ToolConfig) -> ToolBuildResult:
        if progress_callback:
            progress_callback(config.name, "started", None)
        result = build_tool(
            config,
            project_root=project_root,
            no_cache=no_cache,
            pull=pull,
            command_runner=command_runner,
            installed_resolver=installed_resolver,
        )
        if progress_callback:
            progress_callback(config.name, "finished", result.status)
        return result

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 8))) as executor:
        return list(executor.map(execute, configs))


def select_outdated_statuses(*, workers: int = 4) -> list[ToolStatus]:
    """Collect local-only status for repair selection."""

    return collect_tool_statuses(offline=True, workers=workers)


def ensure_docker_ready() -> tuple[bool, str]:
    return docker_daemon_available()
