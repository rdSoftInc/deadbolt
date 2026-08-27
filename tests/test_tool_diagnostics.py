import json

import pytest
from typer.testing import CliRunner

from main.cli.app import app
from main.cli import tools as tools_cli
from main.core import tool_diagnostics
from main.core.tool_diagnostics import (
    CommandResult,
    DoctorCheck,
    ToolStatus,
    _check_engagements,
    classify_tool_status,
    inspect_tool,
    run_doctor,
)
from main.core.engagement import Engagement, save_engagement
from main.core.tool_manifest import get_tool_config
from main.core.provider_config import ProviderStatus


runner = CliRunner()


@pytest.mark.parametrize(
    ("present", "installed", "upstream", "expected_status"),
    [
        (False, None, "1.9.0", "missing"),
        (True, "1.8.1", "1.9.0", "rebuild_required"),
        (True, "unknown", "1.9.0", "unverifiable"),
        (True, "1.9.0", "1.10.0", "update_available"),
        (True, "1.9.0", "1.9.0", "current"),
        (True, "1.9.0", None, "current_offline"),
    ],
)
def test_tool_status_classification(present, installed, upstream, expected_status):
    config = get_tool_config("httpx").model_copy(update={"version": "1.9.0"})
    status, _ = classify_tool_status(
        config=config,
        image_present=present,
        installed=installed,
        upstream=upstream,
    )
    assert status == expected_status


def test_inspect_tool_uses_injected_read_only_resolvers():
    commands = []

    def command_runner(command, timeout):
        commands.append(command)
        return CommandResult(0, "[]", "")

    config = get_tool_config("httpx").model_copy(update={"version": "1.9.0"})
    result = inspect_tool(
        config,
        command_runner=command_runner,
        installed_resolver=lambda image: "1.9.0",
        upstream_resolver=lambda image: "1.9.0",
    )

    assert result.status == "current"
    assert commands == [["docker", "image", "inspect", "deadbolt-httpx"]]


def test_doctor_reports_ready_environment(monkeypatch):
    monkeypatch.setattr(tool_diagnostics, "docker_cli_available", lambda: True)
    monkeypatch.setattr(tool_diagnostics, "_port_available", lambda port: True)

    def command_runner(command, timeout):
        if command[1] == "info":
            return CommandResult(0, "29.0.0\n", "")
        return CommandResult(0, "[]", "")

    checks = run_doctor(command_runner=command_runner)
    by_name = {check.name: check for check in checks}

    assert by_name["docker_daemon"].status == "pass"
    assert by_name["required_images"].status == "pass"
    assert by_name["scope_config"].status == "pass"
    assert by_name["mobsf_port_8000"].status == "pass"
    assert not [check for check in checks if check.status == "fail"]


def test_doctor_skips_images_when_daemon_is_down(monkeypatch):
    monkeypatch.setattr(tool_diagnostics, "docker_cli_available", lambda: True)

    def command_runner(command, timeout):
        return CommandResult(1, "", "daemon unavailable")

    checks = run_doctor(command_runner=command_runner)
    by_name = {check.name: check for check in checks}

    assert by_name["docker_daemon"].status == "fail"
    assert by_name["required_images"].status == "skip"


def test_engagement_health_warns_when_none_are_saved(tmp_path):
    check = _check_engagements(tmp_path)

    assert check.status == "warn"
    assert "none saved" in check.detail


def test_engagement_health_verifies_schema_and_owner_only_permissions(tmp_path):
    engagement = Engagement.model_validate({
        "name": "Authorized Program",
        "engagement_type": "bug_bounty",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"]},
        "traffic": {"automation_allowed": True},
    })
    path = save_engagement(
        engagement,
        tmp_path / "engagements" / "authorized-program.yaml",
    )

    assert _check_engagements(tmp_path).status == "pass"

    path.chmod(0o644)
    warning = _check_engagements(tmp_path)
    assert warning.status == "warn"
    assert "authorized-program.yaml=644" in warning.detail

    path.write_text("name: invalid\n", encoding="utf-8")
    failure = _check_engagements(tmp_path)
    assert failure.status == "fail"
    assert failure.detail == "invalid file(s): authorized-program.yaml"


def test_status_does_not_report_images_missing_when_docker_is_down(monkeypatch):
    monkeypatch.setattr(tool_diagnostics, "docker_cli_available", lambda: True)

    def command_runner(command, timeout):
        return CommandResult(1, "", "daemon unavailable")

    statuses = tool_diagnostics.collect_tool_statuses(
        offline=True,
        command_runner=command_runner,
    )

    assert statuses
    assert {item.status for item in statuses} == {"docker_unavailable"}
    assert {item.image_present for item in statuses} == {None}


def test_status_json_is_machine_readable(monkeypatch):
    sample = ToolStatus(
        name="httpx",
        domains=["web"],
        image="deadbolt-httpx",
        expected="1.9.0",
        installed="1.9.0",
        upstream="1.9.0",
        image_present=True,
        managed=True,
        status="current",
        detail="versions match",
    )
    monkeypatch.setattr(tools_cli, "collect_tool_statuses", lambda **kwargs: [sample])

    result = runner.invoke(app, ["tools", "status", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload[0]["name"] == "httpx"
    assert payload[0]["status"] == "current"


def test_status_returns_failure_for_missing_images(monkeypatch):
    sample = ToolStatus(
        name="httpx",
        domains=["web"],
        image="deadbolt-httpx",
        expected="1.9.0",
        installed=None,
        upstream="1.9.0",
        image_present=False,
        managed=True,
        status="missing",
        detail="image missing",
    )
    monkeypatch.setattr(tools_cli, "collect_tool_statuses", lambda **kwargs: [sample])

    result = runner.invoke(app, ["tools", "status", "--json"])

    assert result.exit_code == 1
    assert json.loads(result.stdout)[0]["status"] == "missing"


def test_status_cli_filters_by_domain(monkeypatch):
    statuses = [
        ToolStatus(
            "httpx", ["web"], "deadbolt-httpx", "1.10.0", "1.10.0", None,
            True, True, "current_offline", "current",
        ),
        ToolStatus(
            "nmap", ["network"], "deadbolt-nmap", "7.991", "7.991", None,
            True, True, "current_offline", "current",
        ),
    ]
    monkeypatch.setattr(tools_cli, "collect_tool_statuses", lambda **kwargs: statuses)

    result = runner.invoke(
        app,
        ["tools", "status", "--offline", "--domain", "network", "--json"],
    )

    assert result.exit_code == 0
    assert [item["name"] for item in json.loads(result.stdout)] == ["nmap"]


def test_provider_status_never_displays_secret_values(monkeypatch):
    monkeypatch.setattr(
        tools_cli,
        "provider_statuses",
        lambda path: [ProviderStatus("shodan", True, ("SHODAN_API_KEY",), ())],
    )

    result = runner.invoke(app, ["tools", "providers"])

    assert result.exit_code == 0
    assert "SHODAN_API_KEY" in result.stdout
    assert "configured" in result.stdout
    assert "secret-value" not in result.stdout


def test_doctor_cli_json_and_exit_code(monkeypatch):
    monkeypatch.setattr(
        tools_cli,
        "run_doctor",
        lambda: [DoctorCheck("docker_daemon", "fail", "not running")],
    )

    result = runner.invoke(app, ["tools", "doctor", "--json"])

    assert result.exit_code == 1
    assert json.loads(result.stdout) == [
        {"name": "docker_daemon", "status": "fail", "detail": "not running"}
    ]
