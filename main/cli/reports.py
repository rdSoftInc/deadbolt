"""Commands for opening and regenerating Deadbolt assessment reports."""

from pathlib import Path
import webbrowser

from click import ClickException
from jinja2 import TemplateError
from rich.console import Console
import typer

from main.report.generator import generate_report


reports_app = typer.Typer(help="Open and regenerate assessment reports.")
console = Console()


def _report_path(run_dir: Path, audience: str) -> Path:
    names = {
        "technical": "technical-report.html",
        "stakeholder": "stakeholder-report.html",
    }
    try:
        name = names[audience.lower()]
    except KeyError as exc:
        raise typer.BadParameter(
            "audience must be technical or stakeholder", param_hint="--audience"
        ) from exc
    return run_dir.resolve() / name


@reports_app.command("generate")
def generate_report_command(
    run_dir: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Assessment run directory containing metadata and normalized findings.",
    ),
) -> None:
    """Generate or refresh both report audiences for an existing run."""

    base = run_dir.resolve()
    try:
        generate_report(base)
    except (FileNotFoundError, OSError, RuntimeError, ValueError, TemplateError) as exc:
        raise ClickException(f"Report generation failed: {exc}") from exc
    console.print(f"[green]✓[/green] technical report: {base / 'technical-report.html'}")
    console.print(f"[green]✓[/green] stakeholder report: {base / 'stakeholder-report.html'}")


@reports_app.command("open")
def open_report_command(
    run_dir: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Assessment run directory.",
    ),
    audience: str = typer.Option(
        "technical",
        "--audience",
        help="Report audience: technical or stakeholder.",
    ),
) -> None:
    """Open one generated report in the default browser."""

    report = _report_path(run_dir.resolve(), audience)
    if not report.is_file():
        raise ClickException(
            f"Report not found: {report}. Generate it with 'deadbolt reports generate {run_dir}'."
        )
    if not webbrowser.open(report.as_uri()):
        raise ClickException(f"The default browser could not open {report}")
    console.print(f"[green]✓[/green] opened {report}")
