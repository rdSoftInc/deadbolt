import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from main.cli.app import app
from main.cli import wizard
from main.core.engagement import Engagement, save_engagement
from main.domains.network.profiles import NetworkScanMode
from main.domains.network.nmap_policy import NetworkPolicyError, build_nmap_plan
from main.domains.network.nmap_executor import (
    NetworkExecutionCancelled,
    PhaseExecution,
    docker_command,
)
from main.domains.network.quality import NetworkQualityError, evaluate_network_quality
from main.domains.network.runner import run_network
from main.domains.network.targets import (
    NetworkTargetError,
    enforce_network_scope,
    parse_network_targets,
)
from main.utils.state import hash_file


def _saved_engagement(tmp_path):
    engagement = Engagement.model_validate({
        "name": "Internal Network",
        "engagement_type": "internal",
        "mode": "standard",
        "scope": {
            "allow_hosts": ["vpn.internal.example"],
            "allow_networks": ["10.20.30.0/24"],
            "deny_networks": ["10.20.30.128/25"],
            "allow_ports": [22, 80, 443],
        },
        "traffic": {"automation_allowed": True},
    })
    return engagement, save_engagement(
        engagement, tmp_path / "engagements" / "internal.yaml"
    )


def _successful_phase(plan, phase, run_dir, *, on_output=None):
    output = Path(phase.arguments[phase.arguments.index("-oX") + 1].removeprefix("/deadbolt/"))
    output_path = run_dir / output
    output_path.parent.mkdir(exist_ok=True)
    output_path.write_text("<?xml version='1.0'?><nmaprun/>\n", encoding="utf-8")
    log = run_dir / "logs" / f"nmap-{phase.name}.log"
    log.parent.mkdir(exist_ok=True)
    log.write_text("complete\n", encoding="utf-8")
    if on_output:
        on_output("Stats: test progress")
    return PhaseExecution(0, 1.25, log)


def test_network_targets_are_canonical_without_expansion(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text(
        "# internal\n10.20.30.4/24\n10.20.30.9\nVPN.INTERNAL.EXAMPLE.\n",
        encoding="utf-8",
    )

    parsed = parse_network_targets(targets)

    assert parsed.values == ("10.20.30.0/24", "10.20.30.9", "vpn.internal.example")
    assert parsed.address_count == 257
    assert parsed.networks == 1
    assert parsed.hostnames == 1


@pytest.mark.parametrize("value", ["https://example.com", "10.0.0.1:443", "bad_host"])
def test_network_targets_reject_urls_ports_and_invalid_hosts(tmp_path, value):
    targets = tmp_path / "targets.txt"
    targets.write_text(value + "\n", encoding="utf-8")

    with pytest.raises(NetworkTargetError):
        parse_network_targets(targets)


def test_network_scope_requires_full_containment_and_honors_denies(tmp_path):
    engagement, _ = _saved_engagement(tmp_path)
    targets = tmp_path / "targets.txt"
    targets.write_text("10.20.30.0/25\nvpn.internal.example\n")
    enforce_network_scope(parse_network_targets(targets), engagement)

    targets.write_text("10.20.30.0/24\n")
    with pytest.raises(NetworkTargetError, match="overlaps a denied network"):
        enforce_network_scope(parse_network_targets(targets), engagement)


def test_network_run_initializes_and_resumes_without_tools(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement, engagement_file = _saved_engagement(tmp_path)
    targets = tmp_path / "network.txt"
    targets.write_text("10.20.30.0/25\n")

    first = run_network(targets, engagement_file, execute=False)
    resumed = run_network(
        first.run_dir / "work" / "input.network-targets.txt",
        engagement_file,
        resume_from=first.run_dir,
        execute=False,
    )

    assert first.status == "initialized"
    assert resumed.resumed is True
    state = json.loads((first.run_dir / "state.json").read_text())
    assert state["domain"] == "network"
    assert state["run"]["awaiting_scanners"] is True
    assert state["tools"]["nmap"]["status"] == "planned"
    assert state["tools"]["nmap"]["version"] == "7.991"
    assert state["tools"]["nmap"]["plan"]["effective_ports"] == [22, 80, 443]
    assert state["tools"]["nmap"]["plan"]["image"] == "deadbolt-nmap:7.991"
    plan_file = first.run_dir / state["tools"]["nmap"]["plan_file"]
    assert plan_file.is_file()
    assert state["tools"]["nmap"]["plan_sha256"] == hash_file(plan_file)
    assert (first.run_dir / state["engagement"]["snapshot"]).stat().st_mode & 0o777 == 0o600
    meta = json.loads((first.run_dir / "meta.json").read_text())
    assert meta["finished_at"] is None
    assert meta["status"] == "initialized"


def test_network_resume_rejects_a_changed_scanner_plan(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _, engagement_file = _saved_engagement(tmp_path)
    targets = tmp_path / "network.txt"
    targets.write_text("10.20.30.0/25\n")
    initialized = run_network(targets, engagement_file, execute=False)
    plan_path = initialized.run_dir / "work" / "nmap-plan.json"
    plan_path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="policy differs"):
        run_network(
            initialized.run_dir / "work" / "input.network-targets.txt",
            engagement_file,
            resume_from=initialized.run_dir,
            execute=False,
        )


def test_network_cli_reports_that_no_packets_were_sent(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _, engagement_file = _saved_engagement(tmp_path)
    targets = tmp_path / "network.txt"
    targets.write_text("10.20.30.0/25\n")

    result = CliRunner().invoke(
        app, ["network", str(targets), "--engagement", str(engagement_file), "--plan-only"]
    )

    assert result.exit_code == 0
    assert "Network assessment initialized" in result.stdout
    assert "no packets were sent" in result.stdout
    assert "standard mode" in result.stdout


def test_guided_network_run_previews_executes_and_links_reports(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement, engagement_file = _saved_engagement(tmp_path)
    answers = iter(["1", "1", "10.20.30.0/25"])
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *args, **kwargs: next(answers))
    confirmations = iter([True, True])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations))
    monkeypatch.setattr("main.domains.network.runner.execute_nmap_phase", _successful_phase)
    messages = []
    monkeypatch.setattr(wizard, "_message", messages.append)

    wizard._network_assessment(engagement_file, engagement)

    runs = list((tmp_path / "outputs").glob("run_*"))
    assert len(runs) == 1
    state = json.loads((runs[0] / "state.json").read_text())
    assert state["domain"] == "network"
    assert state["targets"]["entries"] == 1
    assert state["status"] == "complete"
    assert "Technical report:" in messages[-1]
    assert "Stakeholder report:" in messages[-1]


def test_guided_network_plan_only_saves_plan_without_execution(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement, engagement_file = _saved_engagement(tmp_path)
    answers = iter(["2", "1", "10.20.30.0/25"])
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *args, **kwargs: next(answers))
    confirmations = iter([True, True])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations))
    messages = []
    monkeypatch.setattr(wizard, "_message", messages.append)

    wizard._network_assessment(engagement_file, engagement)

    run = next((tmp_path / "outputs").glob("run_*"))
    state = json.loads((run / "state.json").read_text())
    assert state["status"] == "initialized"
    assert (run / "work" / "nmap-plan.json").is_file()
    assert not (run / "raw").exists()
    assert "Network plan saved:" in messages[-1]
    assert "No packets were sent" in messages[-1]


@pytest.mark.parametrize(
    ("mode", "required", "forbidden", "rate"),
    [
        (NetworkScanMode.SAFE, {"-sT", "-T2"}, {"-sV", "-sS", "-sU", "-O"}, 10.0),
        (NetworkScanMode.STANDARD, {"-sT", "-sV", "--version-light", "-T3"}, {"-sS", "-sU", "-O"}, 100.0),
        (NetworkScanMode.DEEP, {"-sS", "-sV", "--version-all", "-O"}, set(), 500.0),
    ],
)
def test_nmap_modes_compile_explicit_bounded_plans(mode, required, forbidden, rate):
    engagement = Engagement.model_validate({
        "name": "Network policy",
        "engagement_type": "internal",
        "mode": mode.value,
        "scope": {"allow_networks": ["10.0.0.0/24"]},
        "traffic": {"automation_allowed": True},
    })

    plan = build_nmap_plan(engagement, mode)
    tcp = set(plan.phases[0].arguments)

    assert required <= tcp
    assert not forbidden.intersection(tcp)
    assert plan.max_rate == rate
    if mode is NetworkScanMode.SAFE:
        assert plan.nse_scripts == ()
        assert all("--script" not in phase.arguments for phase in plan.phases)
    else:
        assert plan.nse_scripts
        assert "--script" in plan.phases[0].arguments
        assert "--script-timeout" in plan.phases[0].arguments
    assert len(plan.phases) == (2 if mode is NetworkScanMode.DEEP else 1)
    assert plan.phases[-1].requires_raw_socket is (mode is NetworkScanMode.DEEP)
    assert ("--privileged" in tcp) is (mode is NetworkScanMode.DEEP)
    assert ("--unprivileged" in tcp) is (mode is not NetworkScanMode.DEEP)


def test_nmap_plan_enforces_allowed_denied_ports_and_rate_ceiling():
    engagement = Engagement.model_validate({
        "name": "Strict ports",
        "engagement_type": "client",
        "mode": "deep",
        "scope": {
            "allow_networks": ["10.0.0.0/24"],
            "allow_ports": [22, 80, 443],
            "deny_ports": [80],
        },
        "traffic": {"automation_allowed": True, "max_requests_per_second": 1.5},
    })

    plan = build_nmap_plan(engagement, NetworkScanMode.DEEP)

    assert plan.effective_ports == (22, 443)
    assert plan.excluded_ports == (80,)
    assert plan.max_rate == 1.5
    for phase in plan.phases:
        arguments = phase.arguments
        assert arguments[arguments.index("-p") + 1] == "22,443"
        assert "-Pn" in arguments
        assert arguments[arguments.index("--max-rate") + 1] == "1.5"
        assert "-p-" not in arguments


def test_nmap_plan_excludes_denied_ports_when_allow_list_is_open():
    engagement = Engagement.model_validate({
        "name": "Denied ports",
        "engagement_type": "internal",
        "scope": {"allow_networks": ["10.0.0.0/24"], "deny_ports": [23, 445]},
        "traffic": {"automation_allowed": True},
    })

    arguments = build_nmap_plan(engagement, NetworkScanMode.STANDARD).phases[0].arguments

    assert arguments[arguments.index("--exclude-ports") + 1] == "23,445"


def test_nmap_plan_rejects_unauthorized_automation_and_empty_port_scope():
    blocked = Engagement.model_validate({
        "name": "Manual only",
        "engagement_type": "client",
        "scope": {"allow_networks": ["10.0.0.0/24"]},
    })
    with pytest.raises(NetworkPolicyError, match="does not authorize"):
        build_nmap_plan(blocked, NetworkScanMode.SAFE)

    empty = Engagement.model_validate({
        "name": "No effective ports",
        "engagement_type": "client",
        "scope": {
            "allow_networks": ["10.0.0.0/24"],
            "allow_ports": [443],
            "deny_ports": [443],
        },
        "traffic": {"automation_allowed": True},
    })
    with pytest.raises(NetworkPolicyError, match="all explicitly allowed"):
        build_nmap_plan(empty, NetworkScanMode.SAFE)


def test_nmap_docker_command_uses_least_privilege_and_adds_raw_caps_only_when_needed(tmp_path):
    engagement = Engagement.model_validate({
        "name": "Executor",
        "engagement_type": "lab",
        "scope": {"allow_networks": ["127.0.0.1/32"]},
        "traffic": {"automation_allowed": True},
    })
    safe = build_nmap_plan(engagement, NetworkScanMode.SAFE)
    safe_command = docker_command(safe, safe.phases[0], tmp_path, tmp_path / "safe.cid")
    deep = build_nmap_plan(engagement, NetworkScanMode.DEEP)
    deep_command = docker_command(deep, deep.phases[0], tmp_path, tmp_path / "deep.cid")

    assert "--read-only" in safe_command
    assert safe_command[safe_command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges:true" in safe_command
    assert "--cap-add" not in safe_command
    assert "NET_RAW" in deep_command
    assert "NET_ADMIN" in deep_command
    assert safe.image in safe_command


def test_network_execution_fails_then_resumes_only_the_unfinished_phase(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement = Engagement.model_validate({
        "name": "Deep lab",
        "engagement_type": "lab",
        "mode": "deep",
        "scope": {"allow_networks": ["127.0.0.1/32"], "allow_ports": [3000]},
        "traffic": {"automation_allowed": True},
    })
    engagement_file = save_engagement(engagement, tmp_path / "engagements" / "deep.yaml")
    targets = tmp_path / "targets.txt"
    targets.write_text("127.0.0.1\n")
    calls = []

    def fail_udp(plan, phase, run_dir, *, on_output=None):
        calls.append(phase.name)
        if phase.name == "udp_inventory":
            log = run_dir / "logs" / "nmap-udp_inventory.log"
            log.parent.mkdir(exist_ok=True)
            log.write_text("failed\n")
            return PhaseExecution(2, 0.5, log)
        return _successful_phase(plan, phase, run_dir, on_output=on_output)

    first = run_network(targets, engagement_file, phase_executor=fail_udp)
    assert first.status == "failed"
    assert calls == ["tcp_services_os", "udp_inventory"]

    resumed_calls = []

    def resume_success(plan, phase, run_dir, *, on_output=None):
        resumed_calls.append(phase.name)
        return _successful_phase(plan, phase, run_dir, on_output=on_output)

    resumed = run_network(
        first.run_dir / "work" / "input.network-targets.txt",
        engagement_file,
        resume_from=first.run_dir,
        phase_executor=resume_success,
    )

    assert resumed.status == "complete"
    assert resumed.cached_phases == 1
    assert resumed_calls == ["udp_inventory"]
    state = json.loads((first.run_dir / "state.json").read_text())
    assert state["tools"]["nmap"]["phases"]["tcp_services_os"]["status"] == "complete"
    assert state["tools"]["nmap"]["phases"]["udp_inventory"]["status"] == "complete"
    assert state["tools"]["nmap"]["normalized"]["inventory_sha256"]
    assert state["tools"]["nmap"]["normalized"]["quality_sha256"]
    assert (first.run_dir / "normalized" / "network-inventory.json").is_file()
    assert (first.run_dir / "technical-report.html").is_file()
    assert (first.run_dir / "stakeholder-report.html").is_file()


def test_network_execution_splits_explicit_ipv4_and_ipv6_without_duplicating_hostnames(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement = Engagement.model_validate({
        "name": "Dual stack",
        "engagement_type": "internal",
        "mode": "safe",
        "scope": {
            "allow_hosts": ["dual.internal.example"],
            "allow_networks": ["10.0.0.0/24", "2001:db8::/126"],
            "allow_ports": [443],
        },
        "traffic": {"automation_allowed": True},
    })
    engagement_file = save_engagement(engagement, tmp_path / "engagements" / "dual.yaml")
    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.1\n2001:db8::1\ndual.internal.example\n")
    phases = []

    def capture(plan, phase, run_dir, *, on_output=None):
        phases.append(phase)
        return _successful_phase(plan, phase, run_dir, on_output=on_output)

    summary = run_network(targets, engagement_file, phase_executor=capture)

    assert summary.status == "complete"
    assert [phase.name for phase in phases] == ["tcp_inventory", "tcp_inventory_ipv6"]
    assert "-6" not in phases[0].arguments
    assert "-6" in phases[1].arguments
    ipv4 = (summary.run_dir / "work" / "input.network-targets-ipv4.txt").read_text()
    ipv6 = (summary.run_dir / "work" / "input.network-targets-ipv6.txt").read_text()
    assert "10.0.0.1" in ipv4 and "2001:db8::1" not in ipv4
    assert "2001:db8::1" in ipv6 and "10.0.0.1" not in ipv6
    assert "dual.internal.example" in ipv4 and "dual.internal.example" not in ipv6


def test_network_cancellation_is_persisted_for_resume(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _, engagement_file = _saved_engagement(tmp_path)
    targets = tmp_path / "targets.txt"
    targets.write_text("10.20.30.4\n")

    def cancel(*args, **kwargs):
        raise NetworkExecutionCancelled("cancelled")

    with pytest.raises(NetworkExecutionCancelled):
        run_network(targets, engagement_file, phase_executor=cancel)

    run = next((tmp_path / "outputs").glob("run_*"))
    state = json.loads((run / "state.json").read_text())
    assert state["status"] == "interrupted"
    assert state["tools"]["nmap"]["phases"]["tcp_services"]["status"] == "interrupted"
