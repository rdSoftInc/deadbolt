# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file cli.py
# @brief Deadbolt command-line interface entrypoint.
#
# This module defines the primary CLI for Deadbolt using Typer. It acts as the
# orchestration layer that dispatches domain-specific scanning workflows
# (web, Android, iOS) to their respective runners based on user commands.
#
# Each subcommand validates inputs and forwards execution to the appropriate
# domain runner, keeping the CLI layer thin and focused on user interaction.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import typer
from pathlib import Path
from typing import Optional

# Domain-specific execution entrypoints
from main.domains.ios.runner import run_ios
from main.domains.web.runner import run_web
from main.domains.android.runner import run_android
from main.cli.tools import tools_app
from main.cli.reports import reports_app
from main.cli.wizard import run_wizard
from main.version import get_version
from main.utils.local_lab import LocalLabPreflightError
from main.domains.web.profiles import WebScanProfile, normalize_web_profile
from main.domains.network.profiles import NetworkScanMode, normalize_network_mode
from main.domains.network.runner import run_network
from main.domains.network.nmap_executor import NetworkExecutionCancelled
from main.domains.network.targets import NetworkTargetError
from main.core.engagement import EngagementError

# Initialize the Typer application
app = typer.Typer(
    help="Deadbolt – verify the lock, don’t trust the door.",
    invoke_without_command=True,
)
app.add_typer(tools_app, name="tools")
app.add_typer(reports_app, name="reports")


def _version_callback(value: bool):
    if value:
        typer.echo(f"Deadbolt {get_version()}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed Deadbolt version and exit.",
    ),
):
    """
    Deadbolt CLI root callback.

    This function serves as the root entrypoint for the Typer application.
    It is intentionally empty, as all functionality is implemented via
    explicit subcommands (web, android, ios).
    """
    if ctx.invoked_subcommand is None:
        run_wizard()


# ─────────────────────────────
# Web scanning
# ─────────────────────────────

@app.command()
def web(
    targets: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to targets file (domains / URLs)",
    ),
    resume_from: Optional[Path] = typer.Option(
        None,
        "--resume-from",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Resume scan from an existing run directory",
    ),
    local_lab: bool = typer.Option(
        False,
        "--local-lab",
        help="Scan an explicitly local loopback web lab through Docker Desktop.",
    ),
    scope: Optional[Path] = typer.Option(
        None,
        "--scope",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Use an explicit YAML authorization scope instead of scope.yaml.",
    ),
    profile: str = typer.Option(
        WebScanProfile.STANDARD.value,
        "--profile",
        help="Assessment mode: safe, standard, or deep (legacy quick/deep-spa accepted).",
    ),
    browser_assisted: bool = typer.Option(
        False,
        "--browser-assisted",
        help="Capture report-safe Fetch/XHR API traffic without enabling Deep mode.",
    ),
    rate_limit: Optional[float] = typer.Option(
        None,
        "--rate-limit",
        min=1,
        help="Maximum requests per second for rate-aware scanners.",
    ),
):
    """
    Execute a web reconnaissance and vulnerability scan.

    This command validates the provided targets file and optionally resumes
    execution from a previous scan directory. The actual scanning logic is
    delegated to the web domain runner.
    """
    try:
        arguments = dict(
            targets_path=str(targets),
            resume_from=resume_from,
            local_lab=local_lab,
            scan_profile=normalize_web_profile(profile),
        )
        if browser_assisted:
            arguments["browser_assisted"] = True
        if rate_limit is not None:
            arguments["rate_limit"] = rate_limit
        if scope is not None:
            arguments["scope_path"] = scope.resolve()
        run_web(**arguments)
    except LocalLabPreflightError as exc:
        raise typer.ClickException(str(exc)) from exc


@app.command()
def network(
    targets: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to IP, CIDR, and hostname targets"
    ),
    engagement: Path = typer.Option(
        ...,
        "--engagement",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Authorized engagement YAML",
    ),
    mode: Optional[str] = typer.Option(
        None, "--mode", help="Network mode: safe, standard, or deep"
    ),
    resume_from: Optional[Path] = typer.Option(
        None,
        "--resume-from",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Resume an initialized, failed, or interrupted network run",
    ),
    plan_only: bool = typer.Option(
        False,
        "--plan-only",
        help="Validate and persist the exact scanner plan without sending packets",
    ),
):
    """Run an authorized, scope-bound network assessment."""

    def show_progress(phase: str, event: str) -> None:
        if event in {"started", "complete", "cached", "failed"}:
            typer.echo(f"nmap/{phase}: {event}")
        elif "Stats:" in event or "% done" in event:
            typer.echo(f"nmap/{phase}: {event.strip()}")

    try:
        summary = run_network(
            targets,
            engagement,
            mode=normalize_network_mode(mode) if mode else None,
            resume_from=resume_from,
            execute=not plan_only,
            progress=show_progress,
        )
    except NetworkExecutionCancelled as exc:
        raise typer.ClickException(str(exc)) from exc
    except (EngagementError, NetworkTargetError, RuntimeError, ValueError) as exc:
        raise typer.ClickException(str(exc)) from exc
    typer.echo(
        f"Network assessment {summary.status}: {summary.run_id} | "
        f"{summary.targets} target(s) | {summary.address_count} address(es) | "
        f"{summary.mode.value} mode"
    )
    if plan_only:
        typer.echo("Plan-only mode: no packets were sent.")
    else:
        typer.echo(
            f"Nmap phases completed: {summary.completed_phases} "
            f"({summary.cached_phases} restored from resume)."
        )
        if summary.status in {"failed", "processing_failed"}:
            raise typer.Exit(code=1)


# ─────────────────────────────
# Android scanning
# ─────────────────────────────

@app.command()
def android(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to Android APK file",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Optional output directory (defaults to outputs/run_*)",
    ),
):
    """
    Execute static analysis against an Android APK.

    This command performs static inspection of the supplied APK by delegating
    execution to the Android domain runner, which handles decompilation and
    analysis workflows.
    """
    run_android(
        apk_path=apk,
        output_dir=output,
    )


# ─────────────────────────────
# iOS scanning
# ─────────────────────────────

@app.command()
def ios(
    ipa: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to iOS IPA file",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Optional output directory (defaults to outputs/run_*)",
    ),
):
    """
    Execute static analysis against an iOS IPA.

    This command delegates analysis of the supplied IPA file to the iOS
    domain runner, which is responsible for extraction and inspection logic.
    """
    run_ios(
        ipa_path=ipa,
        output_dir=output,
    )


# Entrypoint for direct execution
if __name__ == "__main__":
    app()
