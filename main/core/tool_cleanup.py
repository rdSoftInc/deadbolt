"""Plan and apply conservative cleanup of Deadbolt-owned Docker images."""

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Callable

from main.core.tool_diagnostics import CommandResult, run_command
from main.core.tool_manifest import load_tool_manifest


CommandRunner = Callable[[list[str], float], CommandResult]


def _normalized_ref(image: str) -> str:
    tail = image.rsplit("/", 1)[-1]
    return image if ":" in tail else f"{image}:latest"


def _repository(image: str) -> str:
    normalized = _normalized_ref(image)
    return normalized.rsplit(":", 1)[0]


def _format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TB"


@dataclass(frozen=True)
class CleanupAction:
    target: str
    image_id: str
    tool: str
    reason: str
    estimated_reclaimable_bytes: int = 0

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["estimated_reclaimable"] = _format_bytes(
            self.estimated_reclaimable_bytes
        )
        return payload


@dataclass(frozen=True)
class CleanupPlan:
    actions: list[CleanupAction]
    protected_references: list[str]
    legacy_dangling_count: int

    @property
    def estimated_reclaimable_bytes(self) -> int:
        return sum(item.estimated_reclaimable_bytes for item in self.actions)

    def to_dict(self) -> dict:
        return {
            "actions": [item.to_dict() for item in self.actions],
            "protected_references": self.protected_references,
            "legacy_dangling_count": self.legacy_dangling_count,
            "estimated_reclaimable_bytes": self.estimated_reclaimable_bytes,
            "estimated_reclaimable": _format_bytes(self.estimated_reclaimable_bytes),
        }


def _upgrade_state(path: Path) -> dict:
    if not path.is_file():
        return {"candidates": {}, "rollbacks": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {"candidates": {}, "rollbacks": {}}


def plan_cleanup(
    *,
    command_runner: CommandRunner = run_command,
    state_path: Path | None = None,
) -> CleanupPlan:
    """Inspect images and return only safe Deadbolt-owned removal actions."""

    manifest = load_tool_manifest()
    managed = {name: config for name, config in manifest.tools.items() if config.managed}
    repositories = {_repository(config.image): name for name, config in managed.items()}
    protected = set()
    for config in managed.values():
        protected.update(
            {
                _normalized_ref(config.image),
                _normalized_ref(config.versioned_image),
                _normalized_ref(config.current_image),
            }
        )

    state = _upgrade_state(state_path or Path.cwd() / ".deadbolt" / "tool-upgrades.json")
    for record in state.get("candidates", {}).values():
        if record.get("verified") and record.get("image"):
            protected.add(_normalized_ref(record["image"]))
    for record in state.get("rollbacks", {}).values():
        if record.get("image"):
            protected.add(_normalized_ref(record["image"]))

    listed = command_runner(
        ["docker", "image", "ls", "--all", "-q", "--no-trunc"], 30
    )
    if listed.returncode != 0:
        raise RuntimeError((listed.stderr or listed.stdout or "Docker image listing failed").strip())
    image_ids = sorted(set(line.strip() for line in listed.stdout.splitlines() if line.strip()))
    if not image_ids:
        return CleanupPlan([], sorted(protected), 0)

    inspected = command_runner(["docker", "image", "inspect", *image_ids], 60)
    if inspected.returncode != 0:
        raise RuntimeError((inspected.stderr or inspected.stdout or "Docker image inspection failed").strip())
    payload = json.loads(inspected.stdout)

    actions = []
    legacy_dangling = 0
    for image in payload:
        image_id = str(image.get("Id", ""))
        tags = sorted(_normalized_ref(tag) for tag in (image.get("RepoTags") or []))
        labels = image.get("Config", {}).get("Labels") or {}
        owned = str(labels.get("io.deadbolt.managed", "")).lower() == "true"
        tool = labels.get("io.deadbolt.tool") or "unknown"
        size = int(image.get("Size") or 0)

        if not tags:
            if owned:
                actions.append(
                    CleanupAction(image_id, image_id, tool, "dangling Deadbolt image", size)
                )
            else:
                legacy_dangling += 1
            continue

        removable = [
            tag for tag in tags
            if _repository(tag) in repositories and tag not in protected
        ]
        if not removable:
            continue
        all_tags_removed = len(removable) == len(tags)
        for index, tag in enumerate(removable):
            actions.append(
                CleanupAction(
                    tag,
                    image_id,
                    repositories.get(_repository(tag), tool),
                    "obsolete Deadbolt tag",
                    size if all_tags_removed and index == len(removable) - 1 else 0,
                )
            )

    return CleanupPlan(actions, sorted(protected), legacy_dangling)


def apply_cleanup(
    plan: CleanupPlan,
    *,
    command_runner: CommandRunner = run_command,
) -> list[tuple[CleanupAction, CommandResult]]:
    """Apply an explicit cleanup plan without pruning global Docker state."""

    return [
        (action, command_runner(["docker", "image", "rm", action.target], 60))
        for action in plan.actions
    ]


def format_bytes(value: int) -> str:
    """Public display helper for CLI output."""

    return _format_bytes(value)
