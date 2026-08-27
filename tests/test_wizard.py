import json
from pathlib import Path

from typer.testing import CliRunner

from main.cli.app import app
from main.cli import wizard
from main.core.engagement import Engagement, load_engagement, save_engagement


runner = CliRunner()


def _answers(monkeypatch, values):
    iterator = iter(values)
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *args, **kwargs: next(iterator))


def test_root_wizard_can_exit(monkeypatch):
    _answers(monkeypatch, ["7"])

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "DEADBOLT ( GUIDED MODE )" in result.stdout
    assert "Plan, verify, and run authorized security assessments" in result.stdout
    assert "v1.2.0" in result.stdout
    assert "Goodbye! See you soon" in result.stdout
    assert "Status, build, upgrade, and roll back" in result.stdout


def test_menu_validation_separates_error_from_select_prompt(monkeypatch):
    _answers(monkeypatch, ["", "1"])

    assert wizard._choose("Test menu", ["Continue"]) == 0


def test_root_version_option_does_not_open_wizard():
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "Deadbolt 1.2.0"


def test_web_wizard_teaches_command_and_dispatches_existing_runner(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    targets = tmp_path / "targets.txt"
    targets.write_text("example.com\n", encoding="utf-8")
    _answers(monkeypatch, ["1", "1", "2", "1", "2", str(targets), "2", "5", "7"])
    confirmations = iter([False, True, True])
    monkeypatch.setattr(
        wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations)
    )
    calls = []
    monkeypatch.setattr(
        wizard,
        "run_web",
        lambda **kwargs: calls.append(kwargs),
    )

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "deadbolt web" in result.stdout
    assert "targets.txt" in result.stdout
    assert calls == [{
        "targets_path": str(targets), "resume_from": None, "local_lab": False,
        "scan_profile": wizard.WebScanProfile.STANDARD,
    }]


def test_target_file_picker_discovers_workspace_targets(monkeypatch, tmp_path):
    target_dir = tmp_path / "targets" / "web"
    target_dir.mkdir(parents=True)
    target_file = target_dir / "program.txt"
    target_file.write_text("# scope\nexample.com\napi.example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _answers(monkeypatch, ["1"])

    selected = wizard._select_target_file()

    assert selected == target_file.resolve()


def test_target_file_picker_can_go_back(monkeypatch, tmp_path):
    target_dir = tmp_path / "targets" / "web"
    target_dir.mkdir(parents=True)
    (target_dir / "program.txt").write_text("example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _answers(monkeypatch, ["3"])

    assert wizard._select_target_file() is None


def test_back_after_add_another_file_finishes_current_selection(monkeypatch, tmp_path):
    selected = tmp_path / "program.txt"
    selected.write_text("example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _answers(monkeypatch, [str(selected), "back"])
    confirmations = iter([True])
    monkeypatch.setattr(
        wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations)
    )

    assert wizard._targets_files_bundle() == selected.resolve()


def test_web_wizard_merges_multiple_target_files(monkeypatch, tmp_path):
    first = tmp_path / "program.txt"
    second = tmp_path / "recon.txt"
    first.write_text("example.com\napi.example.com\n", encoding="utf-8")
    second.write_text("# recon\napi.example.com\nadmin.example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _answers(
        monkeypatch,
        ["1", "1", "2", "1", "2", str(first), str(second), "2", "5", "7"],
    )
    confirmations = iter([True, False, True, False])
    monkeypatch.setattr(
        wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations)
    )

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    bundles = list((tmp_path / ".deadbolt" / "targets").glob("bundle-*.txt"))
    assert len(bundles) == 1
    assert bundles[0].read_text(encoding="utf-8") == (
        "example.com\napi.example.com\nadmin.example.com\n"
    )


def test_web_wizard_accepts_direct_targets(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _answers(monkeypatch, ["1", "1", "2", "1", "1", "example.com, https://api.example.com", "2", "5", "7"])
    confirmations = iter([True, False])
    monkeypatch.setattr(
        wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations)
    )

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    generated = list((tmp_path / ".deadbolt" / "targets").glob("interactive-*.txt"))
    assert len(generated) == 1
    assert generated[0].read_text(encoding="utf-8") == "example.com\nhttps://api.example.com\n"
    assert str(generated[0]) in result.stdout.replace("\n", "") or "interactive-" in result.stdout
    assert "Assessment cancelled" in result.stdout


def test_web_resume_lists_runs_newest_first_and_recovers_targets(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    older = tmp_path / "outputs" / "run_20260101_010101"
    newer = tmp_path / "outputs" / "run_20260202_020202"
    for run_dir, target in ((older, "old.example"), (newer, "new.example")):
        (run_dir / "work").mkdir(parents=True)
        (run_dir / "state.json").write_text("{}", encoding="utf-8")
        (run_dir / "work" / "input.targets.txt").write_text(
            f"{target}\n", encoding="utf-8"
        )

    _answers(monkeypatch, ["1", "1", "2", "2", "1", "5", "7"])
    confirmations = iter([True, True])
    monkeypatch.setattr(
        wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations)
    )
    calls = []
    monkeypatch.setattr(wizard, "run_web", lambda **kwargs: calls.append(kwargs))

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert result.stdout.index(newer.name) < result.stdout.index(older.name)
    assert "Choose target input" not in result.stdout
    assert "Target file path" not in result.stdout
    assert "02 Feb 2026, 2:02:02 AM" in result.stdout
    assert newer.name in result.stdout
    assert calls == [{
        "targets_path": str((newer / "work" / "input.targets.txt").resolve()),
        "resume_from": newer.resolve(),
        "local_lab": False,
        "scan_profile": wizard.WebScanProfile.STANDARD,
    }]


def test_run_display_date_prefers_metadata_timestamp(tmp_path):
    run_dir = tmp_path / "outputs" / "run_20260101_010101"
    run_dir.mkdir(parents=True)
    (run_dir / "meta.json").write_text(
        json.dumps({"started_at": "2026-01-03T04:30:00"}),
        encoding="utf-8",
    )

    assert wizard._run_display_date(run_dir) == "03 Jan 2026, 4:30:00 AM"
    assert wizard._run_description(run_dir, None).startswith("03 Jan 2026, 4:30:00 AM")


def test_web_resume_inherits_local_lab_and_deep_profile_from_early_state(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "outputs" / "run_local_failed"
    (run_dir / "work").mkdir(parents=True)
    (run_dir / "state.json").write_text(
        json.dumps({"run": {"local_lab": True, "scan_profile": "deep-spa"}, "tools": {"katana": {"status": "failed"}}}),
        encoding="utf-8",
    )
    (run_dir / "work" / "input.targets.txt").write_text("http://localhost:3000/\n")
    (run_dir / "work" / "targets.transport.txt").write_text("http://host.docker.internal:3000/\n")
    _answers(monkeypatch, ["1", "1", "2", "2", "1", "5", "7"])
    confirmations = iter([True, True])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations))
    calls = []
    monkeypatch.setattr(wizard, "run_web", lambda **kwargs: calls.append(kwargs))

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "--local-lab" in result.stdout
    assert "--profile deep" in result.stdout
    assert calls[0]["local_lab"] is True
    assert calls[0]["scan_profile"] is wizard.WebScanProfile.DEEP


def test_web_resume_hides_cleanly_completed_runs(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    completed = tmp_path / "outputs" / "run_20260303_030303"
    interrupted = tmp_path / "outputs" / "run_20260404_040404"
    for run_dir in (completed, interrupted):
        (run_dir / "work").mkdir(parents=True)
        (run_dir / "state.json").write_text("{}", encoding="utf-8")
        (run_dir / "work" / "input.targets.txt").write_text(
            "example.com\n", encoding="utf-8"
        )
    (completed / "meta.json").write_text(
        json.dumps({"finished_at": "2026-03-03T03:03:03+00:00", "errors": {}}),
        encoding="utf-8",
    )

    choices = iter([0])
    monkeypatch.setattr(wizard, "_choose", lambda *args, **kwargs: next(choices))

    selected = wizard._select_existing_web_run()

    assert selected == (
        interrupted.resolve(),
        (interrupted / "work" / "input.targets.txt").resolve(),
    )


def test_web_wizard_detects_local_lab_and_teaches_flag(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    targets = tmp_path / "juice-shop.txt"
    targets.write_text("http://localhost:3000/#/\n", encoding="utf-8")
    _answers(monkeypatch, ["1", "1", "2", "1", "2", str(targets), "2", "5", "7"])
    confirmations = iter([False, True, True])
    monkeypatch.setattr(
        wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations)
    )
    calls = []
    monkeypatch.setattr(wizard, "run_web", lambda **kwargs: calls.append(kwargs))

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "--local-lab" in result.stdout
    assert "Local lab (Docker host)" in result.stdout
    assert "Standard" in result.stdout
    assert calls == [{
        "targets_path": str(targets),
        "resume_from": None,
        "local_lab": True,
        "scan_profile": wizard.WebScanProfile.STANDARD,
    }]


def test_resume_target_recovery_supports_legacy_run(monkeypatch, tmp_path):
    run_dir = tmp_path / "outputs" / "run_legacy"
    (run_dir / "work").mkdir(parents=True)
    legacy = run_dir / "work" / "targets_domains.txt"
    legacy.write_text("example.com\n", encoding="utf-8")

    assert wizard._recover_run_targets(run_dir) == legacy.resolve()


def test_android_wizard_validates_and_previews_output(monkeypatch, tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    output = tmp_path / "assessment-output"
    _answers(monkeypatch, ["1", "3", str(apk), str(output), "5", "7"])
    confirmations = iter([True, True])
    monkeypatch.setattr(
        wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations)
    )
    calls = []
    monkeypatch.setattr(
        wizard,
        "run_android",
        lambda **kwargs: calls.append(kwargs),
    )

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "deadbolt android" in result.stdout
    assert "--output" in result.stdout
    assert "assessment-output" in result.stdout
    assert calls == [{"apk_path": apk.resolve(), "output_dir": output.resolve()}]


def test_ios_wizard_validates_previews_and_dispatches(monkeypatch, tmp_path):
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(b"PK")
    _answers(monkeypatch, ["1", "4", str(ipa), "", "5", "7"])
    confirmations = iter([True, True])
    monkeypatch.setattr(
        wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations)
    )
    calls = []
    monkeypatch.setattr(wizard, "run_ios", lambda **kwargs: calls.append(kwargs))

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "deadbolt ios" in result.stdout
    assert "automatic outputs/run_*" in result.stdout
    assert calls == [{"ipa_path": ipa.resolve(), "output_dir": None}]


def test_direct_commands_do_not_launch_wizard(monkeypatch):
    monkeypatch.setattr(
        "main.cli.app.run_wizard",
        lambda: (_ for _ in ()).throw(AssertionError("wizard should not launch")),
    )

    result = runner.invoke(app, ["tools", "--help"])

    assert result.exit_code == 0
    assert "Guided security assessment" not in result.stdout


def test_direct_web_local_lab_flag_dispatches_profile(monkeypatch, tmp_path):
    targets = tmp_path / "juice-shop.txt"
    targets.write_text("http://localhost:3000/#/\n")
    calls = []
    monkeypatch.setattr("main.cli.app.run_web", lambda **kwargs: calls.append(kwargs))

    result = runner.invoke(app, ["web", str(targets), "--local-lab"])

    assert result.exit_code == 0
    assert calls == [{
        "targets_path": str(targets),
        "resume_from": None,
        "local_lab": True,
        "scan_profile": wizard.WebScanProfile.STANDARD,
    }]


def test_direct_web_accepts_legacy_deep_spa_profile(monkeypatch, tmp_path):
    targets = tmp_path / "target.txt"
    targets.write_text("example.com\n")
    calls = []
    monkeypatch.setattr("main.cli.app.run_web", lambda **kwargs: calls.append(kwargs))

    result = runner.invoke(app, ["web", str(targets), "--profile", "deep-spa"])

    assert result.exit_code == 0
    assert calls[0]["scan_profile"] is wizard.WebScanProfile.DEEP


def test_direct_web_dispatches_bounty_safe_browser_options(monkeypatch, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://example.com\n")
    calls = []
    monkeypatch.setattr("main.cli.app.run_web", lambda **kwargs: calls.append(kwargs))

    result = runner.invoke(app, [
        "web", str(targets), "--profile", "safe", "--browser-assisted",
        "--rate-limit", "5",
    ])

    assert result.exit_code == 0
    assert calls[0]["scan_profile"] is wizard.WebScanProfile.SAFE
    assert calls[0]["browser_assisted"] is True
    assert calls[0]["rate_limit"] == 5.0


def test_engagement_picker_lists_valid_saved_engagements(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement = Engagement.model_validate({
        "name": "Acme External",
        "engagement_type": "client",
        "mode": "standard",
        "scope": {"allow_hosts": ["example.com"]},
    })
    path = save_engagement(engagement, tmp_path / "engagements" / "acme.yaml")
    _answers(monkeypatch, ["1"])

    selected = wizard._select_engagement()

    assert selected == (path, engagement)


def test_engagement_review_redacts_header_values(tmp_path):
    engagement = Engagement.model_validate({
        "name": "Private Program",
        "engagement_type": "bug_bounty",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"]},
        "traffic": {
            "automation_allowed": True,
            "headers": {"X-Bug-Bounty": "secret-researcher-value"},
        },
    })

    with wizard.console.capture() as capture:
        wizard.console.print(wizard._engagement_panel(tmp_path / "program.yaml", engagement))
    rendered = capture.get()

    assert "secret-researcher-value" not in rendered


def test_engagement_review_explains_web_and_network_readiness(tmp_path):
    engagement = Engagement.model_validate({
        "name": "Restricted Program",
        "engagement_type": "bug_bounty",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"], "exclude_paths": ["/logout"]},
        "traffic": {"automation_allowed": True, "headers": {"X-Researcher": "secret"}},
    })

    with wizard.console.capture() as capture:
        wizard.console.print(wizard._engagement_panel(tmp_path / "program.yaml", engagement))
    rendered = capture.get()

    assert "Web readiness" in rendered
    assert "required headers" in rendered
    assert "path exclusions" in rendered
    assert "Network readiness" in rendered
    assert "secret" not in rendered


def test_packaged_engagement_example_is_ready_for_safe_web_launch():
    engagement = load_engagement(Path("engagements/example.yaml"))

    assert engagement.mode == "safe"
    assert wizard._web_engagement_blockers(engagement) == []


def test_engagement_web_launch_uses_saved_scope_and_mode(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement = Engagement.model_validate({
        "name": "Acme Web",
        "engagement_type": "client",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"], "deny_hosts": ["admin.example.com"]},
        "traffic": {"automation_allowed": True, "max_requests_per_second": 1},
    })
    engagement_file = save_engagement(
        engagement, tmp_path / "engagements" / "acme-web.yaml"
    )
    _answers(monkeypatch, ["1", "1", "example.com", "1"])
    confirmations = iter([True, True])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations))
    calls = []
    monkeypatch.setattr(wizard, "run_web", lambda **kwargs: calls.append(kwargs))

    wizard._web_assessment(engagement, engagement_file)

    assert calls[0]["scan_profile"] is wizard.WebScanProfile.SAFE
    assert calls[0]["scope_path"].is_file()
    assert "example.com" in calls[0]["scope_path"].read_text()
    assert "admin.example.com" in calls[0]["scope_path"].read_text()


def test_engagement_web_launch_uses_saved_targets_without_reentry(
    monkeypatch, tmp_path,
):
    monkeypatch.chdir(tmp_path)
    engagement = Engagement.model_validate({
        "name": "Acme Saved Targets",
        "engagement_type": "bug_bounty",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"]},
        "traffic": {"automation_allowed": True, "max_requests_per_second": 1},
        "web_targets": ["https://example.com/login"],
    })
    engagement_file = save_engagement(
        engagement, tmp_path / "engagements" / "acme-saved.yaml"
    )
    # New scan, saved targets, engagement profile, browser-assisted capture.
    _answers(monkeypatch, ["1", "1", "1", "1"])
    previews = []
    monkeypatch.setattr(
        wizard, "_preview", lambda **kwargs: previews.append(kwargs) or True,
    )
    calls = []
    monkeypatch.setattr(wizard, "run_web", lambda **kwargs: calls.append(kwargs))

    wizard._web_assessment(engagement, engagement_file)

    target_path = Path(calls[0]["targets_path"])
    assert target_path.read_text(encoding="utf-8") == (
        "https://example.com/login\n"
    )
    assert "engagement-acme-saved-targets-web-" in target_path.name
    assert ("Saved targets", "https://example.com/login") in previews[0]["details"]


def test_bug_bounty_engagement_offers_safe_browser_capture_and_rate_cap(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement = Engagement.model_validate({
        "name": "Bounty Web",
        "engagement_type": "bug_bounty",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"]},
        "traffic": {"automation_allowed": True, "max_requests_per_second": 5},
    })
    engagement_file = save_engagement(
        engagement, tmp_path / "engagements" / "bounty-web.yaml"
    )
    _answers(monkeypatch, ["1", "1", "example.com", "1", "1"])
    confirmations = iter([True, True])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations))
    calls = []
    monkeypatch.setattr(wizard, "run_web", lambda **kwargs: calls.append(kwargs))

    wizard._web_assessment(engagement, engagement_file)

    assert calls[0]["scan_profile"] is wizard.WebScanProfile.SAFE
    assert calls[0]["browser_assisted"] is True
    assert calls[0]["rate_limit"] == 5


def test_saved_engagement_allows_one_time_profile_override(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement = Engagement.model_validate({
        "name": "Bounty Override",
        "engagement_type": "bug_bounty",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"]},
        "traffic": {"automation_allowed": True, "max_requests_per_second": 5},
    })
    engagement_file = save_engagement(
        engagement, tmp_path / "engagements" / "bounty-override.yaml"
    )
    # New scan, direct input, choose one-time override, Standard, enable browser capture.
    _answers(monkeypatch, ["1", "1", "example.com", "2", "2", "1"])
    confirmations = iter([True, True])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations))
    calls = []
    monkeypatch.setattr(wizard, "run_web", lambda **kwargs: calls.append(kwargs))

    wizard._web_assessment(engagement, engagement_file)

    assert calls[0]["scan_profile"] is wizard.WebScanProfile.STANDARD
    assert load_engagement(engagement_file).mode == "safe"


def test_engagement_blocks_automation_when_rules_disallow_it(monkeypatch, tmp_path):
    engagement = Engagement.model_validate({
        "name": "Manual Only",
        "engagement_type": "bug_bounty",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"]},
    })
    called = []
    monkeypatch.setattr(wizard, "_web_assessment", lambda *args: called.append(args))

    wizard._start_from_engagement(tmp_path / "manual.yaml", engagement)

    assert called == []


def test_scanner_status_menu_teaches_offline_command(monkeypatch, capsys):
    _answers(monkeypatch, ["2", "3"])
    calls = []
    monkeypatch.setattr(
        wizard,
        "tool_status_command",
        lambda **kwargs: calls.append(kwargs),
    )

    wizard._tool_status_menu()

    assert calls == [{"as_json": False, "offline": True, "workers": 4, "domains": None}]
    assert "deadbolt tools status --offline" in capsys.readouterr().out


def test_scanner_build_menu_builds_one_selected_tool(monkeypatch, capsys):
    _answers(monkeypatch, ["2", "1", "1", "5"])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: True)
    calls = []
    monkeypatch.setattr(
        wizard,
        "tool_build_command",
        lambda **kwargs: calls.append(kwargs),
    )

    wizard._tool_build_menu()

    assert calls == [{
        "tools": ["nmap"],
        "domains": None,
        "outdated": False,
        "parallel": 1,
        "no_cache": False,
        "pull": False,
        "as_json": False,
    }]
    assert "deadbolt tools build --tool nmap --parallel 1" in capsys.readouterr().out


def test_upgrade_menu_promotes_only_recorded_verified_candidate(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    state = tmp_path / ".deadbolt" / "tool-upgrades.json"
    state.parent.mkdir()
    state.write_text(json.dumps({
        "schema": 1,
        "candidates": {
            "httpx": {"from": "1.9.0", "to": "1.10.0", "verified": True},
            "ffuf": {"from": "2.1.0", "to": "2.2.1", "verified": False},
        },
        "rollbacks": {},
    }))
    _answers(monkeypatch, ["3", "1", "5"])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: True)
    calls = []
    monkeypatch.setattr(
        wizard,
        "tool_upgrade_promote_command",
        lambda **kwargs: calls.append(kwargs),
    )

    wizard._tool_upgrade_menu()

    assert calls == [{"tool": "httpx", "verbose": False}]


def test_cleanup_menu_is_dry_run_until_user_confirms(monkeypatch):
    _answers(monkeypatch, ["1", "2"])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: False)
    calls = []
    monkeypatch.setattr(
        wizard,
        "tool_cleanup_command",
        lambda **kwargs: calls.append(kwargs),
    )

    wizard._tool_cleanup_menu()

    assert calls == [{"apply": False, "as_json": False}]


def test_assessment_history_classifies_and_sorts_runs(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    completed = tmp_path / "outputs" / "run_20260101_010101"
    failed = tmp_path / "outputs" / "run_20260202_020202"
    for run in (completed, failed):
        (run / "normalized").mkdir(parents=True)
        (run / "normalized" / "findings.json").write_text("[]")
    (completed / "meta.json").write_text(json.dumps({
        "domain": "web",
        "finished_at": "2026-01-01T01:01:01+00:00",
        "errors": {},
    }))
    (completed / "state.json").write_text(json.dumps({"tools": {"httpx": {"status": "done"}}}))
    (failed / "meta.json").write_text(json.dumps({
        "domain": "network",
        "status": "failed",
        "finished_at": "2026-02-02T02:02:02+00:00",
        "errors": {"nmap": "failed"},
    }))
    (failed / "state.json").write_text(json.dumps({
        "domain": "network", "status": "failed", "tools": {"nmap": {"status": "failed"}}
    }))

    all_runs = wizard._assessment_runs()
    attention = wizard._assessment_runs(resumable_only=True)

    assert [item.path.name for item in all_runs] == [failed.name, completed.name]
    assert all_runs[0].status == "failed"
    assert all_runs[1].status == "complete"
    assert [item.path.name for item in attention] == [failed.name]


def test_assessment_history_lists_id_before_readable_timestamp(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    run = tmp_path / "outputs" / "run_20260303_030303"
    run.mkdir(parents=True)
    (run / "meta.json").write_text(json.dumps({
        "domain": "web",
        "started_at": "2026-03-03T03:03:03",
        "finished_at": "2026-03-03T03:04:03",
        "errors": {},
    }))
    (run / "state.json").write_text(json.dumps({"tools": {"httpx": {"status": "done"}}}))
    _answers(monkeypatch, ["2"])

    assert wizard._select_assessment_run() is None

    output = capsys.readouterr().out
    assert output.index(run.name) < output.index("03 Mar 2026, 3:03:03 AM")


def test_previous_assessment_resumes_selected_web_run_directly(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    run = tmp_path / "outputs" / "run_20260404_040404"
    (run / "work").mkdir(parents=True)
    targets = run / "work" / "input.targets.txt"
    targets.write_text("example.com\n")
    (run / "state.json").write_text(json.dumps({
        "tools": {"httpx": {"status": "failed"}}
    }))
    record = wizard._assessment_run(run)
    calls = []
    monkeypatch.setattr(wizard, "_web_assessment", lambda **kwargs: calls.append(kwargs))

    wizard._resume_assessment_run(record)

    assert calls == [{"resume_selection": (run.resolve(), targets.resolve())}]


def test_web_history_resume_reuses_preserved_scope_snapshot(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    run = tmp_path / "outputs" / "run_20260404_050505"
    (run / "work").mkdir(parents=True)
    (run / "scope").mkdir()
    targets = run / "work" / "input.targets.txt"
    targets.write_text("example.com\n")
    snapshot = run / "scope" / "authorized.yaml"
    snapshot.write_text("allowed_domains:\n  - example.com\ndenied_domains: []\n")
    (run / "meta.json").write_text(json.dumps({
        "domain": "web",
        "scan_profile": "standard",
        "scope_snapshot": "scope/authorized.yaml",
        "errors": {"katana": "interrupted"},
    }))
    (run / "state.json").write_text(json.dumps({
        "tools": {"katana": {"status": "failed"}}
    }))
    confirmations = iter([True, True])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations))
    calls = []
    monkeypatch.setattr(wizard, "run_web", lambda **kwargs: calls.append(kwargs))

    wizard._web_assessment(resume_selection=(run.resolve(), targets.resolve()))

    assert calls[0]["scope_path"] == snapshot.resolve()
    assert calls[0]["resume_from"] == run.resolve()


def test_interrupted_web_history_resume_reuses_state_scope_snapshot(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    run = tmp_path / "outputs" / "run_20260404_060606"
    (run / "work").mkdir(parents=True)
    (run / "scope").mkdir()
    targets = run / "work" / "input.targets.txt"
    targets.write_text("secure.example.com\n")
    snapshot = run / "scope" / "authorized.yaml"
    snapshot.write_text("allow:\n  - secure.example.com\ndeny: []\n")
    (run / "state.json").write_text(json.dumps({
        "run": {"scan_profile": "safe", "local_lab": False},
        "scope": {"snapshot": "scope/authorized.yaml"},
        "tools": {"httpx_paths": {"status": "interrupted"}},
    }))
    confirmations = iter([True, True])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations))
    calls = []
    monkeypatch.setattr(wizard, "run_web", lambda **kwargs: calls.append(kwargs))

    wizard._web_assessment(resume_selection=(run.resolve(), targets.resolve()))

    assert calls[0]["scope_path"] == snapshot.resolve()
    assert calls[0]["resume_from"] == run.resolve()


def test_completed_run_actions_do_not_offer_resume(monkeypatch, tmp_path):
    run = tmp_path / "outputs" / "run_20260505_050505"
    run.mkdir(parents=True)
    (run / "meta.json").write_text(json.dumps({
        "domain": "web", "finished_at": "2026-05-05T05:05:05", "errors": {}
    }))
    (run / "state.json").write_text(json.dumps({"tools": {"httpx": {"status": "done"}}}))
    record = wizard._assessment_run(run)
    menus = []

    def choose(title, options):
        menus.append((title, [getattr(item, "label", item) for item in options]))
        return len(options) - 1

    monkeypatch.setattr(wizard, "_choose", choose)

    wizard._manage_assessment_run(record)

    assert menus[0][1] == ["Reports", "Artifacts", "Back"]


def _report_run(tmp_path, name, domain="web", reports=True):
    run = tmp_path / "outputs" / name
    (run / "normalized").mkdir(parents=True)
    (run / "meta.json").write_text(json.dumps({
        "domain": domain,
        "started_at": "2026-06-06T06:06:06",
        "finished_at": "2026-06-06T06:07:06",
        "errors": {},
    }))
    (run / "state.json").write_text(json.dumps({"tools": {}}))
    (run / "normalized" / "findings.json").write_text("[]")
    if reports:
        (run / "technical-report.html").write_text("<html>technical</html>")
        (run / "stakeholder-report.html").write_text("<html>stakeholder</html>")
    return run


def test_report_library_lists_only_generated_reports(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    older = _report_run(tmp_path, "run_20260606_060606", "web", reports=True)
    _report_run(tmp_path, "run_20260707_070707", "network", reports=False)

    records = wizard._report_runs()
    report_ready = wizard._report_runs(generated_only=False)

    assert [item.path for item in records] == [older.resolve()]
    assert [item.domain for item in report_ready] == ["network", "web"]


def test_report_library_filters_by_assessment_type(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    web = _report_run(tmp_path, "run_20260606_060606", "web")
    _report_run(tmp_path, "run_20260707_070707", "network")

    records = wizard._report_runs(domain="web")

    assert [item.path for item in records] == [web.resolve()]


def test_reports_menu_uses_newest_generated_run(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _report_run(tmp_path, "run_20260606_060606", "web")
    newest = _report_run(tmp_path, "run_20260707_070707", "network")
    choices = iter([0, 4])
    monkeypatch.setattr(wizard, "_choose", lambda *args, **kwargs: next(choices))
    selected = []
    monkeypatch.setattr(wizard, "_manage_report_run", lambda record: selected.append(record))

    wizard._reports_menu()

    assert [item.path for item in selected] == [newest.resolve()]


def test_report_refresh_teaches_command_and_requires_confirmation(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    run = _report_run(tmp_path, "run_20260606_060606", "web")
    record = wizard._assessment_run(run)
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: True)
    calls = []
    monkeypatch.setattr(
        wizard,
        "generate_report_command",
        lambda **kwargs: calls.append(kwargs),
    )

    wizard._generate_run_reports(record)

    assert calls == [{"run_dir": run.resolve()}]
    output = capsys.readouterr().out
    assert "deadbolt reports generate" in output
    assert run.name in output


def test_environment_health_runs_complete_doctor(monkeypatch, capsys):
    choices = iter([0, 4])
    monkeypatch.setattr(wizard, "_choose", lambda *args, **kwargs: next(choices))
    calls = []
    monkeypatch.setattr(
        wizard,
        "tool_doctor_command",
        lambda **kwargs: calls.append(kwargs),
    )

    wizard._environment_health_menu()

    assert calls == [{"as_json": False}]
    assert "deadbolt tools doctor" in capsys.readouterr().out


def test_assessment_readiness_checks_only_selected_domain(monkeypatch, capsys):
    _answers(monkeypatch, ["2"])
    calls = []
    monkeypatch.setattr(
        wizard,
        "tool_status_command",
        lambda **kwargs: calls.append(kwargs),
    )

    wizard._assessment_readiness()

    assert calls == [{
        "as_json": False,
        "offline": True,
        "workers": 4,
        "domains": ["network"],
    }]
    assert "deadbolt tools status --offline --domain network" in capsys.readouterr().out


def test_start_assessment_lists_only_implemented_domains(monkeypatch):
    menus = []
    choices = iter([1, 4])

    def choose(title, options):
        menus.append((title, [getattr(item, "label", item) for item in options]))
        return next(choices)

    monkeypatch.setattr(wizard, "_choose", choose)
    calls = []
    monkeypatch.setattr(wizard, "_start_network_assessment", lambda: calls.append("network"))

    wizard._start_assessment()

    assert menus[0][1] == [
        "Web application", "Network", "Android application", "iOS application", "Back"
    ]
    assert "API" not in menus[0][1]
    assert calls == ["network"]


def test_direct_network_start_uses_selected_engagement(monkeypatch, tmp_path):
    engagement = Engagement.model_validate({
        "name": "Internal Network",
        "engagement_type": "internal",
        "mode": "safe",
        "scope": {"allow_networks": ["10.0.0.0/24"]},
        "traffic": {"automation_allowed": True},
    })
    path = tmp_path / "engagements" / "network.yaml"
    monkeypatch.setattr(wizard, "_engagement_for_assessment", lambda: (path, engagement))
    calls = []
    monkeypatch.setattr(wizard, "_network_assessment", lambda *args: calls.append(args))

    wizard._start_network_assessment()

    assert calls == [(path, engagement)]


def test_web_start_can_use_saved_engagement(monkeypatch, tmp_path):
    engagement = Engagement.model_validate({
        "name": "Bug Bounty",
        "engagement_type": "bug_bounty",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"]},
        "traffic": {"automation_allowed": True, "max_requests_per_second": 1},
    })
    path = tmp_path / "engagements" / "program.yaml"
    choices = iter([0])
    monkeypatch.setattr(wizard, "_choose", lambda *args, **kwargs: next(choices))
    monkeypatch.setattr(wizard, "_engagement_for_assessment", lambda: (path, engagement))
    calls = []
    monkeypatch.setattr(wizard, "_web_assessment", lambda *args: calls.append(args))

    wizard._start_web_assessment()

    assert calls == [(engagement, path)]


def test_mobile_runner_failure_returns_to_guided_mode(monkeypatch, tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    _answers(monkeypatch, [str(apk), ""])
    confirmations = iter([True, True])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: next(confirmations))
    monkeypatch.setattr(
        wizard,
        "run_android",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("analysis failed")),
    )
    messages = []
    monkeypatch.setattr(wizard, "_message", messages.append)

    wizard._mobile_assessment("Android")

    assert "analysis failed" in messages[-1]


def test_start_flow_can_create_first_engagement(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement = Engagement.model_validate({
        "name": "First Program",
        "engagement_type": "bug_bounty",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"]},
        "traffic": {"automation_allowed": True},
    })
    monkeypatch.setattr(wizard, "_engagement_files", lambda: [])
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: True)
    monkeypatch.setattr(wizard, "_collect_engagement", lambda: engagement)

    selected = wizard._engagement_for_assessment()

    assert selected[1] == engagement
    assert selected[0].is_file()
    assert selected[0].parent == (tmp_path / "engagements").resolve()


def test_engagement_creation_requires_draft_confirmation(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    engagement = Engagement.model_validate({
        "name": "Unconfirmed Program",
        "engagement_type": "bug_bounty",
        "mode": "safe",
        "scope": {"allow_hosts": ["example.com"]},
    })
    choices = iter([0, 4])
    monkeypatch.setattr(wizard, "_choose", lambda *args, **kwargs: next(choices))
    monkeypatch.setattr(wizard, "_collect_engagement", lambda *args: engagement)
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *args, **kwargs: False)

    wizard._engagements_menu()

    assert not (tmp_path / "engagements" / "unconfirmed-program.yaml").exists()


def test_saved_engagement_validation_flags_permissions_and_invalid_yaml(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    engagement = Engagement.model_validate({
        "name": "Manual Program",
        "engagement_type": "client",
        "mode": "standard",
        "scope": {"allow_hosts": ["example.com"]},
    })
    valid = save_engagement(engagement, tmp_path / "engagements" / "manual.yaml")
    valid.chmod(0o644)
    invalid = tmp_path / "engagements" / "invalid.yaml"
    invalid.write_text("name: broken\n")

    wizard._validate_saved_engagements()

    output = capsys.readouterr().out
    assert "permissions 644" in output
    assert "expected 600" in output
    assert "invalid.yaml" in output
    assert "1 warning(s)" in output
    assert "1 invalid" in output


def test_invalid_engagement_diagnostics_redact_rejected_values(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "engagements"
    root.mkdir()
    (root / "unsafe.yaml").write_text(
        "schema_version: 1\n"
        "name: Unsafe\n"
        "engagement_type: bug_bounty\n"
        "mode: safe\n"
        "scope:\n  allow_hosts: [example.com]\n"
        "traffic:\n  headers:\n    X-Researcher: \"top-secret-value\\r\\nInjected: true\"\n"
    )

    wizard._validate_saved_engagements()

    output = capsys.readouterr().out
    assert "unsafe.yaml" in output
    assert "traffic.headers" in output
    assert "top-secret-value" not in output


def test_workspace_scope_review_warns_on_empty_allowlist(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text("allow: []\ndeny:\n  - blocked.example\n")

    with wizard.console.capture() as capture:
        wizard.console.print(wizard._workspace_scope_panel(scope))
    rendered = capture.get()

    assert "Unsafe: allowlist is empty" in rendered
    assert "blocked.example" in rendered
