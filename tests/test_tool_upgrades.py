import json
from pathlib import Path

from main.core.tool_diagnostics import CommandResult
from main.core.tool_manifest import get_tool_config
from main.core.tool_upgrades import (
    candidate_image,
    discover_upgrades,
    promote_candidate,
    test_upgrade_candidate as run_candidate_test,
)


def test_candidate_images_are_isolated_from_active_aliases():
    assert candidate_image(get_tool_config("httpx"), "1.10.0") == "deadbolt-httpx:candidate-1.10.0"
    assert candidate_image(get_tool_config("mobsf"), "4.5.2").endswith(":v4.5.2")


def test_upgrade_plan_does_not_mutate_manifest():
    config = get_tool_config("httpx")
    candidates = discover_upgrades(
        ["httpx"], resolver=lambda image: "9.9.9"
    )

    assert candidates[0].status == "update_available"
    assert candidates[0].current == config.display_version
    assert candidates[0].candidate_image == "deadbolt-httpx:candidate-9.9.9"


def test_verified_candidate_is_recorded_without_retagging_active_image(monkeypatch, tmp_path):
    monkeypatch.setattr("main.core.tool_builds.get_tool_version.cache_clear", lambda: None)
    commands = []

    def command_runner(command, timeout):
        commands.append(command)
        return CommandResult(0, "ok", "")

    result = run_candidate_test(
        get_tool_config("httpx"),
        "1.10.0",
        command_runner=command_runner,
        installed_resolver=lambda image: "1.10.0",
        state_path=Path(tmp_path) / "state.json",
    )

    assert result.status == "success"
    build = commands[0]
    assert "deadbolt-httpx:candidate-1.10.0" in build
    assert "deadbolt-httpx:current" not in build
    assert "deadbolt-httpx" not in [build[index + 1] for index, value in enumerate(build[:-1]) if value == "--tag"]


def test_promotion_rechecks_candidate_and_creates_rollback_tag(monkeypatch, tmp_path):
    config = get_tool_config("httpx")
    state_path = Path(tmp_path) / "state.json"
    state_path.write_text(
        json.dumps({
            "schema": 1,
            "candidates": {
                "httpx": {
                    "from": config.version,
                    "to": "9.9.9",
                    "image": "deadbolt-httpx:candidate-9.9.9",
                    "verified": True,
                }
            },
            "rollbacks": {},
        }),
        encoding="utf-8",
    )
    commands = []
    manifest_updates = []
    def installed_version(image):
        return "9.9.9"

    installed_version.cache_clear = lambda: None
    monkeypatch.setattr("main.core.tool_upgrades.get_tool_version", installed_version)
    monkeypatch.setattr(
        "main.core.tool_upgrades._update_manifest_pin",
        lambda name, version, image=None: manifest_updates.append((name, version, image)),
    )

    result = promote_candidate(
        "httpx",
        state_path=state_path,
        command_runner=lambda command, timeout: commands.append(command) or CommandResult(0),
    )

    assert result.returncode == 0
    assert ["docker", "image", "inspect", "deadbolt-httpx:candidate-9.9.9"] in commands
    assert ["docker", "tag", "deadbolt-httpx", f"deadbolt-httpx:rollback-{config.display_version}"] in commands
    assert manifest_updates == [("httpx", "9.9.9", None)]
