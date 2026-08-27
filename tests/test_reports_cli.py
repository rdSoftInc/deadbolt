from typer.testing import CliRunner

from main.cli.app import app
from main.cli import reports as reports_cli


runner = CliRunner()


def test_reports_generate_command_uses_existing_run(monkeypatch, tmp_path):
    run = tmp_path / "run_20260101_010101"
    run.mkdir()
    calls = []
    monkeypatch.setattr(reports_cli, "generate_report", lambda path: calls.append(path))

    result = runner.invoke(app, ["reports", "generate", str(run)])

    assert result.exit_code == 0
    assert calls == [run.resolve()]
    assert "technical report" in result.stdout
    assert "stakeholder report" in result.stdout


def test_reports_open_command_selects_audience(monkeypatch, tmp_path):
    run = tmp_path / "run_20260101_010101"
    run.mkdir()
    stakeholder = run / "stakeholder-report.html"
    stakeholder.write_text("<html></html>")
    opened = []
    monkeypatch.setattr(
        reports_cli.webbrowser,
        "open",
        lambda uri: opened.append(uri) or True,
    )

    result = runner.invoke(
        app,
        ["reports", "open", str(run), "--audience", "stakeholder"],
    )

    assert result.exit_code == 0
    assert opened == [stakeholder.resolve().as_uri()]


def test_reports_open_explains_missing_report(tmp_path):
    run = tmp_path / "run_20260101_010101"
    run.mkdir()

    result = runner.invoke(app, ["reports", "open", str(run)])

    assert result.exit_code == 1
    assert "Report not found" in result.output
    assert "reports generate" in result.output
