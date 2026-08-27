import json
from pathlib import Path

from typer.testing import CliRunner

from main.cli.app import app
from main.cli import tools as tools_cli
from main.core.tool_cleanup import CleanupAction, CleanupPlan, apply_cleanup, plan_cleanup
from main.core.tool_diagnostics import CommandResult


runner = CliRunner()


def _image(image_id, tags, size=100, *, owned=False, tool=None):
    labels = {}
    if owned:
        labels = {"io.deadbolt.managed": "true", "io.deadbolt.tool": tool or "unknown"}
    return {
        "Id": image_id,
        "RepoTags": tags,
        "Size": size,
        "Config": {"Labels": labels},
    }


def test_cleanup_preserves_active_candidate_rollback_and_unrelated_images(tmp_path):
    state = tmp_path / "upgrades.json"
    state.write_text(json.dumps({
        "candidates": {"httpx": {"image": "deadbolt-httpx:candidate-2.0.0", "verified": True}},
        "rollbacks": {"httpx": {"image": "deadbolt-httpx:rollback-1.9.0"}},
    }))
    images = [
        _image("sha256:active", ["deadbolt-httpx:latest", "deadbolt-httpx:current", "deadbolt-httpx:1.10.0"], owned=True, tool="httpx"),
        _image("sha256:rollback", ["deadbolt-httpx:rollback-1.9.0", "deadbolt-httpx:1.9.0"], 200, owned=True, tool="httpx"),
        _image("sha256:candidate", ["deadbolt-httpx:candidate-2.0.0"], owned=True, tool="httpx"),
        _image("sha256:obsolete", ["deadbolt-httpx:candidate-0.9.0"], 300, owned=True, tool="httpx"),
        _image("sha256:dangling-owned", None, 400, owned=True, tool="httpx"),
        _image("sha256:dangling-legacy", None, 500),
        _image("sha256:juice", ["bkimminich/juice-shop:latest"], 600),
    ]

    def command_runner(command, timeout):
        if command[:5] == ["docker", "image", "ls", "--all", "-q"]:
            return CommandResult(0, "\n".join(item["Id"] for item in images))
        if command[:3] == ["docker", "image", "inspect"]:
            return CommandResult(0, json.dumps(images))
        raise AssertionError(command)

    plan = plan_cleanup(command_runner=command_runner, state_path=state)
    targets = [item.target for item in plan.actions]

    assert "deadbolt-httpx:1.9.0" in targets
    assert "deadbolt-httpx:candidate-0.9.0" in targets
    assert "sha256:dangling-owned" in targets
    assert "deadbolt-httpx:rollback-1.9.0" not in targets
    assert "deadbolt-httpx:candidate-2.0.0" not in targets
    assert "bkimminich/juice-shop:latest" not in targets
    assert "sha256:dangling-legacy" not in targets
    assert plan.legacy_dangling_count == 1
    assert plan.estimated_reclaimable_bytes == 700


def test_apply_cleanup_removes_only_explicit_plan_targets():
    plan = CleanupPlan(
        [CleanupAction("deadbolt-httpx:old", "sha256:old", "httpx", "obsolete", 10)],
        [],
        0,
    )
    commands = []
    results = apply_cleanup(
        plan,
        command_runner=lambda command, timeout: commands.append(command) or CommandResult(0),
    )

    assert commands == [["docker", "image", "rm", "deadbolt-httpx:old"]]
    assert results[0][1].returncode == 0


def test_cleanup_cli_is_dry_run_by_default(monkeypatch):
    plan = CleanupPlan(
        [CleanupAction("deadbolt-httpx:old", "sha256:old", "httpx", "obsolete", 10)],
        [],
        0,
    )
    monkeypatch.setattr(tools_cli, "ensure_docker_ready", lambda: (True, "ready"))
    monkeypatch.setattr(tools_cli, "plan_cleanup", lambda: plan)
    monkeypatch.setattr(
        tools_cli,
        "execute_cleanup",
        lambda plan: (_ for _ in ()).throw(AssertionError("dry run mutated Docker")),
    )

    result = runner.invoke(app, ["tools", "cleanup"])

    assert result.exit_code == 0
    assert "Dry Run" in result.stdout
    assert "--apply" in result.stdout


def test_cleanup_summary_has_space_above_and_below_estimate(monkeypatch):
    plan = CleanupPlan([], [], 0)
    monkeypatch.setattr(tools_cli, "ensure_docker_ready", lambda: (True, "ready"))
    monkeypatch.setattr(tools_cli, "plan_cleanup", lambda: plan)

    result = runner.invoke(app, ["tools", "cleanup"])

    assert result.exit_code == 0
    assert "\nEstimated reclaimable: 0.0 B\n\n" in result.stdout
    assert "\n\nNo Deadbolt-owned image cleanup is required." in result.stdout
