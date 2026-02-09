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

# Initialize the Typer application
app = typer.Typer(
    help="Deadbolt – verify the lock, don’t trust the door.",
    invoke_without_command=False,
)


@app.callback()
def main():
    """
    Deadbolt CLI root callback.

    This function serves as the root entrypoint for the Typer application.
    It is intentionally empty, as all functionality is implemented via
    explicit subcommands (web, android, ios).
    """
    pass


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
):
    """
    Execute a web reconnaissance and vulnerability scan.

    This command validates the provided targets file and optionally resumes
    execution from a previous scan directory. The actual scanning logic is
    delegated to the web domain runner.
    """
    run_web(
        targets_path=str(targets),
        resume_from=resume_from,
    )


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
        ios_path=ipa,
        output_dir=output,
    )


# Entrypoint for direct execution
if __name__ == "__main__":
    app()