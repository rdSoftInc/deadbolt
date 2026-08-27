import json

from typer.testing import CliRunner

from main.cli.app import app
from main.cli import tools as tools_cli
from main.core.tool_builds import (
    ToolBuildResult,
    build_command,
    build_tool,
    build_tools,
    select_tools,
)
from main.core import tool_builds
from main.core.tool_diagnostics import CommandResult, ToolStatus
from main.core.tool_manifest import get_tool_config


runner = CliRunner()


def test_managed_build_command_has_manifest_arg_and_three_aliases():
    config = get_tool_config("httpx")

    command, tags = build_command(config, no_cache=True, pull=True)

    assert command[:4] == ["docker", "build", "--no-cache", "--pull"]
    assert ["--build-arg", f"TOOL_VERSION={config.version}"] == command[4:6]
    assert ["--label", "io.deadbolt.managed=true"] == command[6:8]
    assert "io.deadbolt.tool=httpx" in command
    assert f"io.deadbolt.version={config.display_version}" in command
    assert tags == ["deadbolt-httpx", config.versioned_image, "deadbolt-httpx:current"]
    for tag in tags:
        assert ["--tag", tag] == command[command.index(tag) - 1:command.index(tag) + 1]


def test_commit_build_uses_full_sha_and_short_version_tag():
    config = get_tool_config("hakrawler")

    command, tags = build_command(config)

    assert f"TOOL_COMMIT={config.version}" in command
    assert "deadbolt-hakrawler:52a16fe" in tags


def test_external_tool_is_pulled_by_exact_pin():
    config = get_tool_config("mobsf")

    command, tags = build_command(config)

    assert command == ["docker", "pull", config.image]
    assert tags == [config.image]


def test_selection_filters_by_name_domain_and_local_drift():
    status = ToolStatus(
        "httpx", ["web"], "deadbolt-httpx", "1.9.0", "1.8.0", None,
        True, True, "rebuild_required", "mismatch"
    )

    selected = select_tools(names=["httpx"], domains=["web"], statuses=[status], outdated=True)

    assert [item.name for item in selected] == ["httpx"]


def test_selection_accepts_network_domain():
    selected = select_tools(domains=["network"])

    assert [item.name for item in selected] == ["nmap"]


def test_successful_build_must_pass_version_verification(monkeypatch):
    monkeypatch.setattr("main.core.tool_builds.get_tool_version.cache_clear", lambda: None)
    config = get_tool_config("httpx")

    result = build_tool(
        config,
        command_runner=lambda command, timeout: CommandResult(0, "done", ""),
        installed_resolver=lambda image: "1.8.0",
    )

    assert result.status == "failed"
    assert not result.verified
    assert "verification failed" in result.detail


def test_parallel_build_reports_start_and_finish(monkeypatch):
    monkeypatch.setattr("main.core.tool_builds.get_tool_version.cache_clear", lambda: None)
    events = []

    results = build_tools(
        [get_tool_config("httpx")],
        command_runner=lambda command, timeout: CommandResult(0, "done", ""),
        installed_resolver=lambda image: get_tool_config("httpx").display_version,
        progress_callback=lambda name, event, status: events.append((name, event, status)),
    )

    assert results[0].status == "success"
    assert events == [("httpx", "started", None), ("httpx", "finished", "success")]


def test_build_cli_json_and_exit_code(monkeypatch):
    sample = ToolBuildResult(
        "httpx", "build", "deadbolt-httpx", "1.9.0",
        ["deadbolt-httpx", "deadbolt-httpx:1.9.0", "deadbolt-httpx:current"],
        "success", "1.9.0", True, 1.25, "verified"
    )
    monkeypatch.setattr(tools_cli, "ensure_docker_ready", lambda: (True, "29.0.0"))
    monkeypatch.setattr(tools_cli, "build_tools", lambda selected, **kwargs: [sample])

    result = runner.invoke(app, ["tools", "build", "--tool", "httpx", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)[0]["verified"] is True


def test_build_failure_keeps_decisive_go_requirement():
    noise = "\n".join(["later build output"] * 12)
    result = CommandResult(
        1,
        stderr="httpx requires go >= 1.26 (running go 1.25.13)\n" + noise,
    )

    assert "requires go >= 1.26" in tool_builds._tail_error(result)
