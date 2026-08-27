"""Tool lifecycle status and environment diagnostics CLI."""

import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
import typer

from main.core.tool_diagnostics import (
    collect_tool_statuses,
    run_doctor,
    run_streaming_command,
)
from main.core.tool_builds import (
    build_tools,
    ensure_docker_ready,
    select_outdated_statuses,
    select_tools,
)
from main.core.tool_manifest import load_tool_manifest
from main.core.tool_cleanup import (
    apply_cleanup as execute_cleanup,
    format_bytes,
    plan_cleanup,
)
from main.core.tool_upgrades import (
    discover_upgrades,
    promote_candidate,
    rollback_upgrade,
    test_upgrade_candidate,
)
from main.execution.latest_version import get_latest_pin
from main.core.provider_config import provider_statuses


tools_app = typer.Typer(help="Inspect Deadbolt scanner lifecycle and readiness.")
upgrade_app = typer.Typer(help="Test, promote, and roll back scanner upgrades.")
tools_app.add_typer(upgrade_app, name="upgrade")
console = Console()


STATUS_STYLE = {
    "current": "green",
    "current_offline": "cyan",
    "update_available": "yellow",
    "rebuild_required": "yellow",
    "unverifiable": "magenta",
    "missing": "red",
    "docker_unavailable": "red",
}


@tools_app.command("cleanup")
def cleanup_command(
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Apply the displayed Deadbolt-only cleanup plan.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Find obsolete Deadbolt image tags; dry-run unless --apply is supplied."""

    daemon_ok, detail = ensure_docker_ready()
    if not daemon_ok:
        if as_json:
            typer.echo(json.dumps({"status": "failed", "detail": detail}, indent=2))
        else:
            console.print(f"[red]Docker unavailable:[/red] {detail}")
        raise typer.Exit(code=1)
    try:
        plan = plan_cleanup()
    except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[red]Cleanup inspection failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if as_json and not apply:
        typer.echo(json.dumps(plan.to_dict(), indent=2))
        return

    if not as_json:
        table = Table(title="Deadbolt Image Cleanup — Apply" if apply else "Deadbolt Image Cleanup — Dry Run")
        table.add_column("Tool", style="bold cyan")
        table.add_column("Remove")
        table.add_column("Reason")
        table.add_column("Potential reclaim", justify="right")
        for action in plan.actions:
            table.add_row(
                action.tool,
                action.target,
                action.reason,
                format_bytes(action.estimated_reclaimable_bytes)
                if action.estimated_reclaimable_bytes else "shared",
            )
        console.print(table)
        console.print()
        console.print(
            f"[bold]Estimated reclaimable:[/bold] "
            f"{format_bytes(plan.estimated_reclaimable_bytes)}"
        )
        console.print()
        if plan.legacy_dangling_count:
            console.print(
                f"[yellow]![/yellow] {plan.legacy_dangling_count} unlabelled dangling image(s) "
                "were left untouched because ownership cannot be proven."
            )

    if not apply:
        if not as_json:
            if plan.actions:
                console.print("\n[dim]Review the plan, then run with --apply to remove only these references.[/dim]")
            else:
                console.print("[green]No Deadbolt-owned image cleanup is required.[/green]")
        return

    results = execute_cleanup(plan)
    failures = []
    payload = []
    for action, result in results:
        success = result.returncode == 0
        payload.append({
            "target": action.target,
            "status": "removed" if success else "failed",
            "detail": (result.stderr or result.stdout).strip(),
        })
        if not success:
            failures.append((action, result))
        elif not as_json:
            console.print(f"[green]✓[/green] removed {action.target}")
    if as_json:
        typer.echo(json.dumps({"plan": plan.to_dict(), "results": payload}, indent=2))
    for action, result in failures:
        if not as_json:
            console.print(
                f"[red]✗[/red] {action.target}: "
                f"{(result.stderr or result.stdout).strip()}"
            )
    if failures:
        raise typer.Exit(code=1)


@upgrade_app.command("plan")
def upgrade_plan_command(
    tools: Optional[list[str]] = typer.Option(None, "--tool", "-t"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show available upgrades without changing images or the manifest."""

    try:
        if as_json:
            candidates = discover_upgrades(tools or ())
        else:
            with console.status("[cyan]Checking upstream releases…[/cyan]"):
                candidates = discover_upgrades(tools or ())
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if as_json:
        typer.echo(json.dumps([item.to_dict() for item in candidates], indent=2))
        return
    table = Table(title="Deadbolt Upgrade Plan")
    table.add_column("Tool", style="bold cyan")
    table.add_column("Current")
    table.add_column("Upstream")
    table.add_column("Candidate image")
    table.add_column("Status")
    for item in candidates:
        style = "yellow" if item.status == "update_available" else "green"
        table.add_row(
            item.name, item.current, item.upstream or "—", item.candidate_image or "—",
            f"[{style}]{item.status.replace('_', ' ')}[/{style}]",
        )
    console.print(table)


@upgrade_app.command("test")
def upgrade_test_command(
    tools: Optional[list[str]] = typer.Option(None, "--tool", "-t"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Stream Docker build output."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Build isolated candidates and record only versions that verify."""

    daemon_ok, detail = ensure_docker_ready()
    if not daemon_ok:
        raise typer.BadParameter(f"Docker unavailable: {detail}")
    try:
        if as_json:
            planned = discover_upgrades(tools or ())
        else:
            with console.status("[cyan]Checking upstream releases…[/cyan]"):
                planned = discover_upgrades(tools or ())
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    available = [item for item in planned if item.status == "update_available"]
    results = []
    manifest = load_tool_manifest()
    for item in available:
        config = manifest.tools[item.name]
        version = get_latest_pin(config.image)
        if not version:
            continue
        if not as_json:
            console.print(f"[cyan]Testing candidate[/cyan] {item.name} {item.current} → {item.upstream}")
        if verbose:
            results.append(
                test_upgrade_candidate(
                    config,
                    version,
                    no_cache=no_cache,
                    pull=True,
                    command_runner=run_streaming_command,
                )
            )
        elif as_json:
            results.append(
                test_upgrade_candidate(config, version, no_cache=no_cache, pull=True)
            )
        else:
            with console.status(
                f"[cyan]Building and verifying[/cyan] {item.name} {item.upstream}"
            ):
                results.append(
                    test_upgrade_candidate(config, version, no_cache=no_cache, pull=True)
                )
    if as_json:
        typer.echo(json.dumps([item.to_dict() for item in results], indent=2))
    elif not results:
        console.print("[green]No selected upgrades are available.[/green]")
    else:
        for result in results:
            style = "green" if result.status == "success" else "red"
            console.print(f"[{style}]{result.status}[/{style}] {result.name}: {result.detail}")
    if any(item.status != "success" for item in results):
        raise typer.Exit(code=1)


@upgrade_app.command("promote")
def upgrade_promote_command(
    tool: str = typer.Option(..., "--tool", "-t"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show every Docker operation."),
) -> None:
    """Promote one previously verified candidate and retain a rollback tag."""

    if verbose:
        result = promote_candidate(tool, command_runner=run_streaming_command)
    else:
        with console.status(f"[cyan]Verifying and promoting[/cyan] {tool}"):
            result = promote_candidate(tool)
    if result.returncode != 0:
        console.print(f"[red]Promotion failed:[/red] {(result.stderr or result.stdout).strip()}")
        raise typer.Exit(code=1)
    console.print(f"[green]✓[/green] {result.stdout.strip()}")


@upgrade_app.command("rollback")
def upgrade_rollback_command(
    tool: str = typer.Option(..., "--tool", "-t"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show every Docker operation."),
) -> None:
    """Restore the previous manifest pin and runtime image for one tool."""

    if verbose:
        result = rollback_upgrade(tool, command_runner=run_streaming_command)
    else:
        with console.status(f"[cyan]Verifying and rolling back[/cyan] {tool}"):
            result = rollback_upgrade(tool)
    if result.returncode != 0:
        console.print(f"[red]Rollback failed:[/red] {(result.stderr or result.stdout).strip()}")
        raise typer.Exit(code=1)
    console.print(f"[green]✓[/green] {result.stdout.strip()}")


@tools_app.command("build")
def build_command(
    tools: Optional[list[str]] = typer.Option(
        None, "--tool", "-t", help="Build one tool; repeat to select several."
    ),
    domains: Optional[list[str]] = typer.Option(
        None, "--domain", "-d", help="Build tools in a domain: web, network, android, or ios."
    ),
    outdated: bool = typer.Option(
        False, "--outdated", help="Repair only missing, mismatched, or unverifiable images."
    ),
    parallel: int = typer.Option(
        1, "--parallel", "-j", min=1, max=8, help="Concurrent Docker operations."
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable Docker build cache."),
    pull: bool = typer.Option(False, "--pull", help="Refresh managed base images."),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Build pinned scanners, pull external images, and verify installed versions."""

    daemon_ok, daemon_detail = ensure_docker_ready()
    if not daemon_ok:
        if as_json:
            typer.echo(json.dumps({"status": "failed", "detail": daemon_detail}, indent=2))
        else:
            console.print(f"[red]Docker unavailable:[/red] {daemon_detail}")
        raise typer.Exit(code=1)

    statuses = select_outdated_statuses(workers=parallel) if outdated else None
    try:
        selected = select_tools(
            names=tools or (), domains=domains or (), statuses=statuses, outdated=outdated
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if not selected:
        if as_json:
            typer.echo("[]")
        else:
            console.print("[green]No selected tools require a build or pull.[/green]")
        return

    if as_json:
        results = build_tools(
            selected,
            workers=parallel,
            no_cache=no_cache,
            pull=pull,
        )
    else:
        task_ids: dict[str, int] = {}
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            for config in selected:
                action = "build" if config.managed else "pull"
                task_ids[config.name] = progress.add_task(
                    f"[dim]waiting[/dim] {action} {config.name}", total=None
                )

            def update_progress(name: str, event: str, status: str | None) -> None:
                task_id = task_ids[name]
                config = next(item for item in selected if item.name == name)
                action = "building" if config.managed else "pulling"
                if event == "started":
                    progress.update(task_id, description=f"[cyan]{action}[/cyan] {name}")
                else:
                    style = "green" if status == "success" else "red"
                    progress.update(
                        task_id,
                        description=f"[{style}]{status}[/{style}] {name}",
                        completed=1,
                        total=1,
                    )

            results = build_tools(
                selected,
                workers=parallel,
                no_cache=no_cache,
                pull=pull,
                progress_callback=update_progress,
            )
    if as_json:
        typer.echo(json.dumps([item.to_dict() for item in results], indent=2))
    else:
        table = Table(title="Deadbolt Tool Build")
        table.add_column("Tool", style="bold cyan")
        table.add_column("Action")
        table.add_column("Expected")
        table.add_column("Installed")
        table.add_column("Seconds", justify="right")
        table.add_column("Status")
        for item in results:
            style = "green" if item.status == "success" else "red"
            table.add_row(
                item.name,
                item.action,
                item.expected,
                item.installed or "—",
                f"{item.duration_seconds:.2f}",
                f"[{style}]{item.status}[/{style}]",
            )
        console.print(table)
        for item in results:
            if item.status == "failed":
                console.print(f"[red]{item.name}:[/red] {item.detail}")

    if any(item.status != "success" for item in results):
        raise typer.Exit(code=1)


@tools_app.command("status")
def status_command(
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    offline: bool = typer.Option(False, "--offline", help="Skip upstream network checks."),
    workers: int = typer.Option(4, "--workers", min=1, max=8, help="Concurrent checks."),
    domains: Optional[list[str]] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Limit status to a domain: web, network, android, or ios.",
    ),
) -> None:
    """Compare configured, installed, and upstream scanner versions."""

    requested_domains = set(domains or ())
    unknown_domains = requested_domains - {"web", "network", "android", "ios"}
    if unknown_domains:
        raise typer.BadParameter(
            "unknown domain(s): " + ", ".join(sorted(unknown_domains)),
            param_hint="--domain",
        )
    if as_json:
        statuses = collect_tool_statuses(offline=offline, workers=workers)
    else:
        message = "Inspecting installed images…" if offline else "Checking installed and upstream versions…"
        with console.status(f"[cyan]{message}[/cyan]"):
            statuses = collect_tool_statuses(offline=offline, workers=workers)
    if requested_domains:
        statuses = [
            item for item in statuses
            if requested_domains.intersection(item.domains)
        ]
    if as_json:
        typer.echo(json.dumps([item.to_dict() for item in statuses], indent=2))
    else:
        table = Table(title="Deadbolt Tool Status")
        table.add_column("Tool", style="bold cyan")
        table.add_column("Domain")
        table.add_column("Expected")
        table.add_column("Installed")
        table.add_column("Upstream")
        table.add_column("Image")
        table.add_column("Status")

        for item in statuses:
            style = STATUS_STYLE.get(item.status, "white")
            table.add_row(
                item.name,
                ",".join(item.domains),
                item.expected,
                item.installed or "—",
                item.upstream or "—",
                "present"
                if item.image_present is True
                else "missing"
                if item.image_present is False
                else "unknown",
                f"[{style}]{item.status.replace('_', ' ')}[/{style}]",
            )
        console.print(table)

    unhealthy = {"docker_unavailable", "missing", "rebuild_required", "unverifiable"}
    if any(item.status in unhealthy for item in statuses):
        raise typer.Exit(code=1)


@tools_app.command("providers")
def providers_command(
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Show optional provider credential readiness without exposing values."""

    statuses = provider_statuses(Path.cwd() / ".env")
    if as_json:
        typer.echo(json.dumps([
            {
                "name": item.name,
                "configured": item.configured,
                "configured_variables": list(item.configured_variables),
                "missing_variables": list(item.missing_variables),
            }
            for item in statuses
        ], indent=2))
        return
    table = Table(title="Deadbolt Optional Providers")
    table.add_column("Provider", style="bold cyan")
    table.add_column("Status")
    table.add_column("Variable readiness", overflow="fold")
    for item in statuses:
        style = "green" if item.configured else "dim"
        details = []
        if item.configured_variables:
            details.append("set: " + ", ".join(item.configured_variables))
        if item.missing_variables:
            details.append("missing: " + ", ".join(item.missing_variables))
        table.add_row(
            item.name,
            f"[{style}]{'configured' if item.configured else 'optional'}[/{style}]",
            "; ".join(details) or "—",
        )
    console.print(table)
    console.print()
    console.print("[dim]Credential values are never displayed. Environment variables override .env.[/dim]")


@tools_app.command("doctor")
def doctor_command(
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Check whether the local Deadbolt installation is ready to scan."""

    if as_json:
        checks = run_doctor()
    else:
        with console.status("[cyan]Checking Deadbolt assessment readiness…[/cyan]"):
            checks = run_doctor()
    if as_json:
        typer.echo(json.dumps([check.to_dict() for check in checks], indent=2))
    else:
        symbols = {"pass": "[green]✓[/green]", "warn": "[yellow]![/yellow]", "skip": "[dim]-[/dim]", "fail": "[red]✗[/red]"}
        for check in checks:
            console.print(f"{symbols[check.status]} [bold]{check.name}[/bold]: {check.detail}")
        counts = {
            status: sum(check.status == status for check in checks)
            for status in ("pass", "warn", "skip", "fail")
        }
        console.print()
        console.print(
            "[bold]Health summary:[/bold] "
            f"[green]{counts['pass']} passed[/green]  •  "
            f"[yellow]{counts['warn']} warning(s)[/yellow]  •  "
            f"[red]{counts['fail']} failed[/red]  •  "
            f"[dim]{counts['skip']} skipped[/dim]"
        )
        if not counts["fail"]:
            console.print(
                "\n[green]Deadbolt's installed components are ready.[/green] "
                "[yellow]Review warnings before each assessment.[/yellow]"
            )
        else:
            failed = {check.name for check in checks if check.status == "fail"}
            actions = []
            if "tool_manifest" in failed:
                actions.append("Repair or reinstall Deadbolt's packaged tool manifest.")
            if "docker_daemon" in failed:
                actions.append("Start Docker Desktop, then run this health check again.")
            if "required_images" in failed:
                actions.append("Run: deadbolt tools build --outdated --parallel 3")
            if "scope_config" in failed:
                actions.append("Review scope.yaml before starting a web assessment.")
            if "saved_engagements" in failed:
                actions.append("Repair or recreate invalid saved engagement files.")
            if failed.intersection({"wordlist_shallow", "wordlist_common"}):
                actions.append("Restore the configured workspace wordlists.")
            if any(name.startswith("report_template_") for name in failed):
                actions.append("Repair the Deadbolt installation to restore report templates.")
            if "targets" in failed:
                actions.append("Create the workspace targets/ directory.")
            console.print("\n[bold yellow]Suggested next actions:[/bold yellow]")
            for action in actions:
                console.print(f"[yellow]•[/yellow] {action}")

    if any(check.status == "fail" for check in checks):
        raise typer.Exit(code=1)
