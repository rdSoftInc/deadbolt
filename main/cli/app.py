import typer
from pathlib import Path
from typing import Optional

from main.core.runner import run_scan

app = typer.Typer(
    help="Deadbolt – verify the lock, don’t trust the door.",
    invoke_without_command=False,
)

@app.callback()
def main():
    """
    Deadbolt pentest orchestrator.
    """
    pass


@app.command()
def run(
    targets: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to targets file"
    ),
    resume_from: Optional[Path] = typer.Option(
        None,
        "--resume-from",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Resume scan from an existing run directory"
    ),
):
    run_scan(
        targets_path=str(targets),
        resume_from=resume_from,
    )


if __name__ == "__main__":
    app()