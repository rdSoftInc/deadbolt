"""Candidate testing, promotion, and rollback for scanner upgrades."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
from typing import Callable, Iterable

from main.core.tool_builds import ToolBuildResult, build_tool
from main.core.tool_diagnostics import CommandResult, run_command
from main.core.tool_manifest import MANIFEST_PATH, ToolConfig, load_tool_manifest
from main.execution.latest_version import get_latest_pin
from main.execution.version import get_tool_version


STATE_PATH = Path.cwd() / ".deadbolt" / "tool-upgrades.json"


@dataclass(frozen=True)
class UpgradeCandidate:
    name: str
    current: str
    upstream: str | None
    candidate_image: str | None
    managed: bool
    status: str

    def to_dict(self) -> dict:
        return asdict(self)


def _repository(image: str) -> str:
    return image.rsplit(":", 1)[0] if ":" in image else image


def candidate_image(config: ToolConfig, version: str) -> str:
    repository = _repository(config.image)
    if config.managed:
        display = version[:7] if config.version_type == "commit" else version
        return f"{repository}:candidate-{display}"
    return f"{repository}:v{version}"


def discover_upgrades(
    names: Iterable[str] = (),
    resolver: Callable[[str], str | None] = get_latest_pin,
) -> list[UpgradeCandidate]:
    manifest = load_tool_manifest()
    requested = set(names)
    unknown = requested - manifest.tools.keys()
    if unknown:
        raise ValueError("unknown tool(s): " + ", ".join(sorted(unknown)))

    configs = [
        config for config in manifest.tools.values()
        if not requested or config.name in requested
    ]
    with ThreadPoolExecutor(max_workers=4) as executor:
        upstream_versions = list(executor.map(lambda item: resolver(item.image), configs))

    candidates = []
    for config, upstream in zip(configs, upstream_versions):
        current = config.version
        available = bool(upstream and upstream.lstrip("v") != current)
        candidates.append(
            UpgradeCandidate(
                config.name,
                config.display_version,
                upstream[:7] if upstream and config.version_type == "commit" else upstream,
                candidate_image(config, upstream) if available and upstream else None,
                config.managed,
                "update_available" if available else "current" if upstream else "unavailable",
            )
        )
    return candidates


def _read_state(path: Path = STATE_PATH) -> dict:
    if not path.is_file():
        return {"schema": 1, "candidates": {}, "rollbacks": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_state(state: dict, path: Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def test_upgrade_candidate(
    config: ToolConfig,
    version: str,
    *,
    no_cache: bool = False,
    pull: bool = True,
    command_runner=run_command,
    installed_resolver=get_tool_version,
    state_path: Path = STATE_PATH,
) -> ToolBuildResult:
    image = candidate_image(config, version)
    candidate = config.model_copy(update={"version": version, "image": image})
    tags = [image] if config.managed else None
    result = build_tool(
        candidate,
        no_cache=no_cache,
        pull=pull,
        image_tags=tags,
        command_runner=command_runner,
        installed_resolver=installed_resolver,
    )
    if result.status == "success" and config.managed and config.version_detection == "image_label":
        smoke = command_runner(["docker", "run", "--rm", image, "--help"], 30)
        if smoke.returncode not in {0, 1, 2}:
            result = replace(
                result,
                status="failed",
                verified=False,
                detail="runtime smoke test failed: " + (smoke.stderr or smoke.stdout).strip(),
            )
    state = _read_state(state_path)
    if result.status == "success":
        state["candidates"][config.name] = {
            "from": config.version,
            "to": version,
            "image": image,
            "verified": True,
        }
    else:
        state["candidates"].pop(config.name, None)
    _write_state(state, state_path)
    return result


def _update_manifest_pin(name: str, version: str, image: str | None = None) -> None:
    lines = MANIFEST_PATH.read_text(encoding="utf-8").splitlines()
    in_tool = False
    found_version = False
    for index, line in enumerate(lines):
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            in_tool = line == f"  {name}:"
        elif in_tool and line.startswith("    version:"):
            lines[index] = f"    version: {version}"
            found_version = True
        elif in_tool and image and line.startswith("    image:"):
            lines[index] = f"    image: {image}"
    if not found_version:
        raise ValueError(f"manifest entry not found: {name}")
    temporary = MANIFEST_PATH.with_suffix(".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(MANIFEST_PATH)
    load_tool_manifest.cache_clear()
    get_tool_version.cache_clear()


def promote_candidate(
    name: str,
    *,
    command_runner=run_command,
    state_path: Path = STATE_PATH,
) -> CommandResult:
    state = _read_state(state_path)
    record = state["candidates"].get(name)
    if not record or not record.get("verified"):
        return CommandResult(2, stderr="no verified candidate; run upgrade test first")
    config = load_tool_manifest().tools[name]
    candidate = record["image"]
    present = command_runner(["docker", "image", "inspect", candidate], 15)
    if present.returncode != 0:
        return CommandResult(2, stderr=f"verified candidate image is missing: {candidate}")
    get_tool_version.cache_clear()
    installed = get_tool_version(candidate)
    expected = record["to"][:7] if config.version_type == "commit" else record["to"]
    if installed != expected:
        return CommandResult(
            2,
            stderr=f"candidate verification changed: installed {installed}, expected {expected}",
        )
    if config.managed:
        repository = _repository(config.image)
        rollback = f"{repository}:rollback-{config.display_version}"
        tags = [
            ["docker", "tag", config.image, rollback],
            ["docker", "tag", candidate, config.image],
            ["docker", "tag", candidate, f"{repository}:{record['to'][:7] if config.version_type == 'commit' else record['to']}"],
            ["docker", "tag", candidate, f"{repository}:current"],
        ]
        for command in tags:
            result = command_runner(command, 30)
            if result.returncode != 0:
                return result
        new_image = None
    else:
        rollback = config.image
        new_image = candidate

    _update_manifest_pin(name, record["to"], new_image)
    state["rollbacks"][name] = {"version": record["from"], "image": rollback}
    state["candidates"].pop(name, None)
    _write_state(state, state_path)
    return CommandResult(0, stdout=f"promoted {name} to {record['to']}")


def rollback_upgrade(
    name: str,
    *,
    command_runner=run_command,
    state_path: Path = STATE_PATH,
) -> CommandResult:
    state = _read_state(state_path)
    record = state["rollbacks"].get(name)
    if not record:
        return CommandResult(2, stderr="no rollback recorded")
    config = load_tool_manifest().tools[name]
    present = command_runner(["docker", "image", "inspect", record["image"]], 15)
    if present.returncode != 0:
        return CommandResult(2, stderr=f"rollback image is missing: {record['image']}")
    if config.managed:
        repository = _repository(config.image)
        for target in (config.image, f"{repository}:current"):
            result = command_runner(["docker", "tag", record["image"], target], 30)
            if result.returncode != 0:
                return result
        new_image = None
    else:
        new_image = record["image"]
    _update_manifest_pin(name, record["version"], new_image)
    state["rollbacks"].pop(name, None)
    _write_state(state, state_path)
    return CommandResult(0, stdout=f"rolled back {name} to {record['version']}")
