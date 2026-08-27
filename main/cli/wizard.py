"""Guided terminal interface over Deadbolt's canonical CLI services."""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shlex
from typing import Callable
import yaml
from click.exceptions import ClickException, Exit

from rich.console import Console, Group
from rich.panel import Panel
from rich.padding import Padding
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from main.domains.android.runner import run_android
from main.domains.ios.runner import run_ios
from main.domains.web.runner import run_web
from main.version import get_version
from main.utils.local_lab import LocalLabPreflightError, normalize_local_lab_targets
from main.utils.resume import resolve_scope_snapshot
from main.domains.web.profiles import WebScanProfile, PROFILE_LABELS, normalize_web_profile
from main.core.scope import ScopeError, load_scope
from main.core.engagement import (
    Engagement,
    EngagementError,
    EngagementScope,
    TrafficPolicy,
    engagement_path,
    engagement_slug,
    load_engagement,
    save_engagement,
)
from main.domains.network.profiles import NetworkScanMode, MODE_DESCRIPTIONS
from main.domains.network.nmap_policy import NetworkPolicyError, build_nmap_plan
from main.domains.network.nmap_executor import NetworkExecutionCancelled
from main.domains.network.runner import run_network
from main.domains.network.targets import NetworkTargetError, parse_network_targets
from main.cli.tools import (
    build_command as tool_build_command,
    cleanup_command as tool_cleanup_command,
    doctor_command as tool_doctor_command,
    providers_command as tool_providers_command,
    status_command as tool_status_command,
    upgrade_plan_command as tool_upgrade_plan_command,
    upgrade_promote_command as tool_upgrade_promote_command,
    upgrade_rollback_command as tool_upgrade_rollback_command,
    upgrade_test_command as tool_upgrade_test_command,
)
from main.cli.reports import (
    generate_report_command,
    open_report_command,
)
from main.core.tool_manifest import ToolConfig, load_tool_manifest


console = Console()


@dataclass(frozen=True)
class MenuOption:
    label: str
    description: str = ""


@dataclass(frozen=True)
class AssessmentRun:
    path: Path
    domain: str
    status: str
    profile: str
    started: str
    findings: int | None
    errors: int
    resumable: bool
    meta: dict
    state: dict


def _option(value: str | MenuOption) -> MenuOption:
    return value if isinstance(value, MenuOption) else MenuOption(value)


def _choose(title: str, options: list[str | MenuOption]) -> int:
    normalized = [_option(item) for item in options]
    console.print()
    console.print(Text(title.upper(), style="bold cyan"))
    table = Table.grid(padding=(0, 1))
    table.add_column(width=4, justify="right", no_wrap=True)
    table.add_column(min_width=24)
    table.add_column(style="dim")
    for index, item in enumerate(normalized, start=1):
        table.add_row(
            f"[bold cyan]{index}[/bold cyan]",
            f"[bold]{item.label}[/bold]",
            item.description,
        )
    console.print(Padding(table, (1, 0)))
    console.print("[dim]Enter a number  •  Ctrl+C to exit[/dim]")
    console.print()
    while True:
        answer = Prompt.ask("[bold cyan]Select[/bold cyan]").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(normalized):
            return int(answer) - 1
        _message("[yellow]Please select one of the available options.[/yellow]")


def _ask(label: str, **kwargs) -> str:
    """Render consistently spaced free-form input prompts."""

    console.print()
    return Prompt.ask(label, **kwargs)


def _message(markup: str) -> None:
    """Separate a status, validation, or result message from prior input."""

    console.print()
    console.print(markup)
    console.print()


def _csv_values(label: str, default: list | None = None) -> list[str]:
    """Collect a compact comma-separated list with edit-friendly defaults."""

    rendered = ", ".join(str(value) for value in (default or []))
    raw = _ask(label, default=rendered).strip()
    return list(dict.fromkeys(value.strip() for value in raw.split(",") if value.strip()))


def _optional_rate(default: float | None = None) -> float | None:
    while True:
        rendered = "" if default is None else str(default)
        raw = _ask("Maximum requests per second (blank for mode default)", default=rendered).strip()
        if not raw:
            return None
        try:
            rate = float(raw)
            if rate > 0:
                return rate
        except ValueError:
            pass
        _message("[yellow]Enter a positive number or leave it blank.[/yellow]")


def _required_file(label: str, suffix: str | None = None) -> Path:
    while True:
        raw = _ask(label).strip().strip("'\"").replace("\\ ", " ")
        path = Path(raw).expanduser()
        if not path.is_file():
            _message(f"[red]File not found:[/red] {path}")
            continue
        if suffix and path.suffix.lower() != suffix:
            _message(f"[red]Expected a {suffix} file:[/red] {path}")
            continue
        return path.resolve()


def _usable_target_count(path: Path) -> int:
    return sum(
        1
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def _select_target_file() -> Path | None:
    """Choose a workspace target file, or return to the preceding menu."""

    workspace = Path.cwd()
    candidates = []
    for root in (workspace / "targets", workspace / ".deadbolt" / "targets"):
        if root.is_dir():
            candidates.extend(path for path in root.rglob("*.txt") if path.is_file())
    candidates = sorted(set(candidates))
    if candidates:
        options = [
            MenuOption(
                str(path.relative_to(workspace)),
                f"{_usable_target_count(path)} target(s)",
            )
            for path in candidates
        ]
        options.append(MenuOption("Enter another path", "Absolute or relative to the workspace"))
        options.append(MenuOption("Back", "Finish selection or return to target input"))
        choice = _choose("Select a target file", options)
        if choice < len(candidates):
            return candidates[choice].resolve()
        if choice == len(candidates) + 1:
            return None
    console.print()
    console.print(f"[dim]Current directory: {workspace}[/dim]")
    console.print("[dim]Tip: you can drag a file from Finder into the terminal.[/dim]")
    while True:
        raw = _ask("Target file path (or 'back')").strip().strip("'\"").replace("\\ ", " ")
        if raw.lower() in {"back", "b"}:
            return None
        path = Path(raw).expanduser()
        if path.is_file():
            return path.resolve()
        _message(f"[red]File not found:[/red] {path}")


def _recover_run_targets(run: Path) -> Path | None:
    """Find the best target input carried by a prior web run."""

    snapshot = run / "work" / "input.targets.txt"
    if snapshot.is_file() and _usable_target_count(snapshot):
        return snapshot.resolve()

    metadata = run / "meta.json"
    if metadata.is_file():
        try:
            recorded = Path(json.loads(metadata.read_text(encoding="utf-8"))["targets_file"])
            if not recorded.is_absolute():
                recorded = Path.cwd() / recorded
            if recorded.is_file() and _usable_target_count(recorded):
                return recorded.resolve()
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
            pass

    legacy = run / "work" / "targets_domains.txt"
    if legacy.is_file() and _usable_target_count(legacy):
        return legacy.resolve()
    return None


def _run_description(run: Path, targets: Path | None) -> str:
    parts = [_run_display_date(run)]
    parts.append(f"{_usable_target_count(targets)} target(s)" if targets else "targets unavailable")
    return "  •  ".join(parts)


def _run_display_date(run: Path) -> str:
    """Return a readable local start time for a completed or interrupted run."""

    started_at = None
    metadata = run / "meta.json"
    if metadata.is_file():
        try:
            payload = json.loads(metadata.read_text(encoding="utf-8"))
            if payload.get("started_at"):
                started_at = datetime.fromisoformat(str(payload["started_at"]))
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    if started_at is None:
        try:
            started_at = datetime.strptime(run.name, "run_%Y%m%d_%H%M%S")
        except ValueError:
            return run.name
    elif started_at.tzinfo is not None:
        started_at = started_at.astimezone()

    return started_at.strftime("%d %b %Y, %I:%M:%S %p").replace(" 0", " ")


def _is_resumable_web_run(run: Path) -> bool:
    """Return whether a run has unfinished or failed work worth resuming."""

    metadata = run / "meta.json"
    if not metadata.is_file():
        # A missing final manifest normally means the process was interrupted.
        return True
    try:
        payload = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        # Keep damaged runs visible so the user has a chance to recover them.
        return True

    if not payload.get("finished_at"):
        return True
    errors = payload.get("errors")
    return bool(errors)


def _select_existing_web_run() -> tuple[Path, Path] | None:
    """List incomplete workspace runs newest first and recover their targets."""

    outputs = Path.cwd() / "outputs"
    runs = sorted(
        (
            path for path in outputs.glob("run_*")
            if (
                path.is_dir()
                and (path / "state.json").is_file()
                and (path / "work").is_dir()
                and _is_resumable_web_run(path)
            )
        ),
        key=lambda path: path.name,
        reverse=True,
    )
    if not runs:
        _message(
            "[yellow]No incomplete or failed web runs were found in outputs/.[/yellow]"
        )
        return None

    recovered = [_recover_run_targets(run) for run in runs]
    options = [
        MenuOption(run.name, _run_description(run, targets))
        for run, targets in zip(runs, recovered)
    ]
    options.append(MenuOption("Back", "Return to web scan options"))
    choice = _choose("Select an existing run", options)
    if choice == len(runs):
        return None

    run, targets = runs[choice].resolve(), recovered[choice]
    if targets is None:
        _message(
            "[yellow]This legacy run does not contain recoverable target information.[/yellow]"
        )
        targets = _required_file("Original target file path")
    return run, targets


def _optional_directory(label: str) -> Path | None:
    value = _ask(label, default="").strip()
    return Path(value).expanduser().resolve() if value else None


def _direct_targets_file() -> Path:
    """Normalize direct wizard input into a stable, reusable targets file."""

    while True:
        raw = _ask("Targets (comma or space separated)").strip()
        targets = [item for chunk in raw.split(",") for item in chunk.split() if item]
        targets = list(dict.fromkeys(targets))
        if targets:
            break
        _message("[red]Enter at least one domain or URL.[/red]")
    content = "\n".join(targets) + "\n"
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    path = Path(".deadbolt") / "targets" / f"interactive-{digest}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _message(f"[dim]Saved {len(targets)} target(s) to {path}[/dim]")
    return path.resolve()


def _direct_network_targets_file() -> Path:
    """Persist direct IP/CIDR/hostname input without expanding networks."""

    while True:
        raw = _ask("Network targets (comma or space separated)").strip()
        values = [item for chunk in raw.split(",") for item in chunk.split() if item]
        values = list(dict.fromkeys(values))
        if values:
            break
        _message("[red]Enter at least one IP, CIDR, or hostname.[/red]")
    content = "\n".join(values) + "\n"
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    path = Path(".deadbolt") / "targets" / f"network-{digest}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path.resolve()


def _engagement_targets_file(engagement: Engagement, domain: str) -> Path:
    """Materialize durable engagement targets for the existing runners."""

    values = engagement.web_targets if domain == "web" else engagement.network_targets
    content = "\n".join(values) + "\n"
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    path = Path(".deadbolt") / "targets" / (
        f"engagement-{engagement_slug(engagement.name)}-{domain}-{digest}.txt"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path.resolve()


def _target_values(path: Path) -> list[str]:
    return list(dict.fromkeys(
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ))


def _targets_files_bundle() -> Path | None:
    """Select one or more target files and merge multiple inputs safely."""

    files = []
    while True:
        selected = _select_target_file()
        if selected is None:
            if files:
                _message(f"[dim]Finished selection with {len(files)} file(s).[/dim]")
            break
        files.append(selected)
        console.print()
        if not Confirm.ask("Add another target file?", default=False):
            break
    if not files:
        return None
    if len(files) == 1:
        return files[0]

    targets = []
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                targets.append(value)
    targets = list(dict.fromkeys(targets))
    if not targets:
        raise ValueError("Selected target files contain no usable targets")
    content = "\n".join(targets) + "\n"
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    bundle = Path(".deadbolt") / "targets" / f"bundle-{digest}.txt"
    bundle.parent.mkdir(parents=True, exist_ok=True)
    bundle.write_text(content, encoding="utf-8")
    _message(
        f"[dim]Merged {len(files)} files into {bundle} "
        f"({len(targets)} unique targets)[/dim]"
    )
    return bundle.resolve()


def _preview(
    *,
    assessment: str,
    target: Path,
    command: list[str],
    details: list[tuple[str, str]],
    start_prompt: str = "Start assessment now?",
) -> bool:
    summary = Table.grid(padding=(0, 1))
    summary.add_column(width=12, justify="right", no_wrap=True, style="bold")
    summary.add_column()
    summary.add_row("Assessment:", assessment)
    summary.add_row("Input:", str(target))
    for label, value in details:
        summary.add_row(f"{label}:", value)
    preview = Group(
        summary,
        Text(),
        Text("Equivalent command:", style="bold"),
        Text(),
        Text(shlex.join(command), style="cyan"),
    )
    console.print()
    console.print(Panel(preview, title="Execution preview", border_style="cyan"))
    console.print()
    if not Confirm.ask(
        "I confirm I am authorized to assess this target",
        default=False,
    ):
        _message("[yellow]Assessment cancelled.[/yellow]")
        return False
    console.print()
    if not Confirm.ask(start_prompt, default=False):
        _message("[yellow]Assessment cancelled.[/yellow]")
        return False
    return True


def _web_assessment(
    engagement: Engagement | None = None,
    engagement_file: Path | None = None,
    resume_selection: tuple[Path, Path] | None = None,
) -> None:
    if resume_selection is not None:
        resume, targets = resume_selection
    else:
        mode = _choose(
            "Web assessment",
            [
                MenuOption("New scan", "Start from a targets file"),
                MenuOption("Resume an existing scan", "Continue an incomplete or failed run"),
                MenuOption("Back", "Return to assessment types"),
            ],
        )
        if mode == 2:
            return
        resume = None
        if mode == 1:
            selection = _select_existing_web_run()
            if selection is None:
                return
            resume, targets = selection
        else:
            if engagement is not None:
                if engagement.web_targets:
                    target_action = _choose(
                        "Engagement targets",
                        [
                            MenuOption(
                                f"Use saved targets ({len(engagement.web_targets)})",
                                "Start from the targets recorded in this engagement (recommended)",
                            ),
                            MenuOption("Edit saved targets", "Replace the engagement's reusable web targets"),
                            MenuOption("Override for this run", "Use different targets without changing the engagement"),
                            MenuOption("Back", "Return to web scan options"),
                        ],
                    )
                    if target_action == 3:
                        return
                    if target_action == 0:
                        targets = _engagement_targets_file(engagement, "web")
                    elif target_action == 1:
                        targets = _direct_targets_file()
                        updated = _replace_engagement_targets(engagement, "web", targets)
                        if updated is None:
                            return
                        engagement = updated
                        save_engagement(engagement, engagement_file)
                        targets = _engagement_targets_file(engagement, "web")
                        _message("[green]✓ Saved engagement web targets updated.[/green]")
                    else:
                        source = _choose(
                            "Temporary target input",
                            [
                                MenuOption("Enter targets directly", "One or more domains or URLs"),
                                MenuOption("Use target file(s)", "Select existing text files with one target per line"),
                                MenuOption("Back", "Return to engagement targets"),
                            ],
                        )
                        if source == 2:
                            return
                        targets = _direct_targets_file() if source == 0 else _targets_files_bundle()
                        if targets is None:
                            return
                else:
                    target_action = _choose(
                        "Engagement targets",
                        [
                            MenuOption("Save targets to engagement", "Enter reusable web targets (recommended)"),
                            MenuOption("Override for this run", "Run without changing the engagement"),
                            MenuOption("Back", "Return to web scan options"),
                        ],
                    )
                    if target_action == 2:
                        return
                    targets = _direct_targets_file()
                    if target_action == 0:
                        updated = _replace_engagement_targets(engagement, "web", targets)
                        if updated is None:
                            return
                        engagement = updated
                        save_engagement(engagement, engagement_file)
                        targets = _engagement_targets_file(engagement, "web")
                        _message("[green]✓ Saved engagement web targets updated.[/green]")
            else:
                source = _choose(
                    "Choose target input",
                    [
                        MenuOption("Enter targets directly", "One or more domains or URLs"),
                        MenuOption("Use target file(s)", "Select existing text files with one target per line"),
                        MenuOption("Back", "Return to web scan options"),
                    ],
                )
                if source == 2:
                    return
                targets = _direct_targets_file() if source == 0 else _targets_files_bundle()
                if targets is None:
                    return
    local_lab = False
    browser_assisted = False
    rate_limit = engagement.traffic.max_requests_per_second if engagement else None
    scan_profile = normalize_web_profile(engagement.mode) if engagement else WebScanProfile.STANDARD
    profile_known = False
    if resume:
        for context_path in (resume / "meta.json", resume / "state.json"):
            if not context_path.is_file():
                continue
            try:
                payload = json.loads(context_path.read_text(encoding="utf-8"))
                context = payload if context_path.name == "meta.json" else payload.get("run", {})
                if "local_lab" in context:
                    local_lab = bool(context["local_lab"])
                if context.get("scan_profile"):
                    scan_profile = normalize_web_profile(context["scan_profile"])
                    profile_known = True
                browser_assisted = bool(context.get("browser_assisted", browser_assisted))
                rate_limit = context.get("rate_limit", rate_limit)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if profile_known:
                break
        if not local_lab and (resume / "work" / "targets.transport.txt").is_file():
            local_lab = True
        if local_lab and not profile_known:
            profile_choice = _choose(
                "Original profile was not recorded; select resume profile",
                [
                    MenuOption("Safe", "Low traffic and non-intrusive checks"),
                    MenuOption("Standard", "Balanced daily assessment"),
                    MenuOption("Deep", "Labs and explicitly authorized comprehensive testing"),
                    MenuOption("Back"),
                ],
            )
            if profile_choice == 3:
                return
            scan_profile = [WebScanProfile.SAFE, WebScanProfile.STANDARD, WebScanProfile.DEEP][profile_choice]
    else:
        try:
            normalize_local_lab_targets(
                [
                    line.strip()
                    for line in targets.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                ]
            )
            local_lab = True
        except ValueError:
            local_lab = False

        if engagement is None:
            profile_choice = _choose(
                "Select scan profile",
                [
                    MenuOption("Safe", "Bug bounty and sensitive production targets"),
                    MenuOption("Standard", "Everyday authorized assessment (recommended)"),
                    MenuOption("Deep", "Labs and explicitly authorized comprehensive testing"),
                    MenuOption("Back", "Return to target input"),
                ],
            )
            if profile_choice == 3:
                return
            scan_profile = [
                WebScanProfile.SAFE,
                WebScanProfile.STANDARD,
                WebScanProfile.DEEP,
            ][profile_choice]
        else:
            saved_profile = normalize_web_profile(engagement.mode)
            profile_action = _choose(
                "Select scan profile",
                [
                    MenuOption(
                        f"Use engagement default — {PROFILE_LABELS[saved_profile]}",
                        "Apply the profile recorded in this engagement (recommended)",
                    ),
                    MenuOption(
                        "Choose for this run",
                        "Override the profile once without changing the engagement",
                    ),
                    MenuOption("Back", "Return to target input"),
                ],
            )
            if profile_action == 2:
                return
            if profile_action == 1:
                profile_choice = _choose(
                    "One-time scan profile",
                    [
                        MenuOption("Safe", "Bug bounty and sensitive production targets"),
                        MenuOption("Standard", "Broader everyday authorized assessment"),
                        MenuOption(
                            "Deep",
                            "Only when the engagement explicitly permits comprehensive testing",
                        ),
                        MenuOption("Back", "Return to profile choice"),
                    ],
                )
                if profile_choice == 3:
                    return
                scan_profile = [
                    WebScanProfile.SAFE,
                    WebScanProfile.STANDARD,
                    WebScanProfile.DEEP,
                ][profile_choice]

        if engagement is not None and engagement.engagement_type == "bug_bounty":
            browser_choice = _choose(
                "Browser-assisted API capture",
                [
                    MenuOption("Enable", "Capture Fetch/XHR methods and API metadata safely (recommended)"),
                    MenuOption("Disable", "Use crawler and static JavaScript discovery only"),
                    MenuOption("Back", "Return to target input"),
                ],
            )
            if browser_choice == 2:
                return
            browser_assisted = browser_choice == 0

    command = ["deadbolt", "web", str(targets)]
    effective_scope = Path("scope.yaml").resolve()
    use_explicit_scope = False
    if resume:
        snapshot = resolve_scope_snapshot(resume)
        if snapshot is not None:
            effective_scope = snapshot
            use_explicit_scope = True
    if engagement is not None:
        scope_payload = engagement.web_scope()
        digest = hashlib.sha256(
            yaml.safe_dump(scope_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()[:12]
        effective_scope = Path(".deadbolt") / "engagement-scopes" / f"{digest}.yaml"
        effective_scope.parent.mkdir(parents=True, exist_ok=True)
        effective_scope.write_text(yaml.safe_dump(scope_payload, sort_keys=False), encoding="utf-8")
        effective_scope.chmod(0o600)
        effective_scope = effective_scope.resolve()
        use_explicit_scope = True
    details = [("Scope", str(effective_scope))]
    if engagement is not None:
        details.insert(0, ("Engagement", engagement.name))
        if engagement_file is not None:
            details.insert(1, ("Engagement file", str(engagement_file)))
        if engagement.web_targets:
            details.insert(2, ("Saved targets", ", ".join(engagement.web_targets)))
    command.extend(["--profile", scan_profile.value])
    if browser_assisted:
        command.append("--browser-assisted")
    if rate_limit is not None:
        command.extend(["--rate-limit", str(rate_limit)])
    if use_explicit_scope:
        command.extend(["--scope", str(effective_scope)])
    details.append(("Scan profile", PROFILE_LABELS[scan_profile]))
    details.append(("Browser API capture", "Enabled" if browser_assisted else "Disabled"))
    if rate_limit is not None:
        details.append(("Traffic ceiling", f"{rate_limit:g} requests/second"))
    policy_summary = {
        WebScanProfile.SAFE: "Low traffic; no port scan, brute force, DAST, or OAST",
        WebScanProfile.STANDARD: "Balanced discovery, enumeration, and safe checks",
        WebScanProfile.DEEP: "Broad discovery, browser crawling, DAST, and optional OAST",
    }
    details.append(("Policy", policy_summary[scan_profile]))
    if local_lab:
        command.append("--local-lab")
        details.append(("Transport", "Local lab (Docker host)"))
    if resume:
        command.extend(["--resume-from", str(resume)])
        details.append(("Resume from", str(resume)))
    if _preview(
        assessment="Web application",
        target=targets,
        command=command,
        details=details,
    ):
        try:
            run_arguments = dict(
                targets_path=str(targets),
                resume_from=resume,
                local_lab=local_lab,
                scan_profile=scan_profile,
                **({"scope_path": effective_scope} if use_explicit_scope else {}),
            )
            if browser_assisted:
                run_arguments["browser_assisted"] = True
            if rate_limit is not None:
                run_arguments["rate_limit"] = rate_limit
            run_web(**run_arguments)
        except (LocalLabPreflightError, ScopeError, ValueError, RuntimeError) as exc:
            _message(f"[red]{exc}[/red]")


def _mobile_assessment(platform: str) -> None:
    suffix = ".apk" if platform == "Android" else ".ipa"
    artifact = _required_file(f"Path to {platform} {suffix.upper()} file", suffix)
    output = _optional_directory("Output directory (leave blank for automatic)")
    command = ["deadbolt", platform.lower(), str(artifact)]
    details = [("Output", str(output) if output else "automatic outputs/run_*")]
    if output:
        command.extend(["--output", str(output)])
    if not _preview(
        assessment=f"{platform} application",
        target=artifact,
        command=command,
        details=details,
    ):
        return
    runner: Callable = run_android if platform == "Android" else run_ios
    argument = {"apk_path": artifact} if platform == "Android" else {"ipa_path": artifact}
    try:
        runner(**argument, output_dir=output)
    except (OSError, RuntimeError, ValueError) as exc:
        _message(f"[red]{exc}[/red]")


def _automation_allowed(engagement: Engagement) -> bool:
    if engagement.traffic.automation_allowed:
        return True
    _message(
        "[red]Active assessment blocked:[/red] this engagement records that "
        "automated testing is not allowed."
    )
    return False


def _web_engagement_blockers(engagement: Engagement) -> list[str]:
    unsupported = []
    if not engagement.traffic.automation_allowed:
        unsupported.append("automation is not allowed")
    if engagement.traffic.headers:
        unsupported.append("required headers")
    if engagement.traffic.user_agent:
        unsupported.append("required user agent")
    if engagement.traffic.max_requests_per_second is not None:
        expected = 1.0 if engagement.mode == "safe" else None
        if expected is None or engagement.traffic.max_requests_per_second != expected:
            unsupported.append("custom rate ceiling")
    if engagement.scope.allow_ports or engagement.scope.deny_ports:
        unsupported.append("port restrictions")
    if engagement.scope.exclude_paths:
        unsupported.append("path exclusions")
    if not engagement.scope.allow_hosts:
        unsupported.append("no authorized web hosts")
    return unsupported


def _start_engagement_web(path: Path, engagement: Engagement) -> None:
    blockers = _web_engagement_blockers(engagement)
    if blockers:
        _message(
            "[yellow]Web launch is blocked by engagement compatibility: "
            + ", ".join(blockers)
            + ".[/yellow]"
        )
        return
    _web_assessment(engagement, path)


def _start_engagement_network(path: Path, engagement: Engagement) -> None:
    if _automation_allowed(engagement):
        _network_assessment(path, engagement)


def _confirm_engagement_save(
    path: Path,
    engagement: Engagement,
    prompt: str,
) -> bool:
    console.print()
    console.print(_engagement_panel(path, engagement, title="Engagement draft"))
    console.print()
    if Confirm.ask(prompt, default=False):
        return True
    _message("[yellow]Engagement changes were not saved.[/yellow]")
    return False


def _engagement_for_assessment() -> tuple[Path, Engagement] | None:
    if _engagement_files():
        return _select_engagement()
    _message("[yellow]No saved engagements were found.[/yellow]")
    if not Confirm.ask("Create an engagement now?", default=True):
        return None
    engagement = _collect_engagement()
    if engagement is None:
        return None
    path = engagement_path(engagement.name)
    if path.exists():
        _message(f"[red]An engagement already exists at:[/red] {path}")
        return None
    if not _confirm_engagement_save(path, engagement, "Save this engagement?"):
        return None
    saved = save_engagement(engagement, path)
    _message(f"[green]Engagement created:[/green] {saved}")
    return saved, engagement


def _start_web_assessment() -> None:
    source = _choose(
        "Web authorization context",
        [
            MenuOption("Saved engagement", "Use recorded scope, policy, and assessment mode (recommended)"),
            MenuOption("Workspace scope.yaml", "Use the existing workspace allow and deny rules"),
            MenuOption("Back", "Return to assessment types"),
        ],
    )
    if source == 0:
        selected = _engagement_for_assessment()
        if selected:
            _start_engagement_web(*selected)
    elif source == 1:
        _web_assessment()


def _start_network_assessment() -> None:
    selected = _engagement_for_assessment()
    if selected:
        _start_engagement_network(*selected)


def _start_assessment() -> None:
    while True:
        choice = _choose(
            "Start an assessment",
            [
                MenuOption("Web application", "Engagement-aware reconnaissance, enumeration, and testing"),
                MenuOption("Network", "Scope-bound discovery and service assessment"),
                MenuOption("Android application", "Static analysis of an APK"),
                MenuOption("iOS application", "Static analysis of an IPA"),
                MenuOption("Back", "Return to the main menu"),
            ],
        )
        if choice == 0:
            _start_web_assessment()
        elif choice == 1:
            _start_network_assessment()
        elif choice == 2:
            _mobile_assessment("Android")
        elif choice == 3:
            _mobile_assessment("iOS")
        else:
            return


def _engagement_files() -> list[Path]:
    root = Path.cwd() / "engagements"
    if not root.is_dir():
        return []
    return sorted(
        (
            path for pattern in ("*.yaml", "*.yml")
            for path in root.glob(pattern)
            if path.name != "example.yaml"
        ),
        key=lambda path: path.name,
    )


def _engagement_error_summary(exc: Exception) -> str:
    """Return useful engagement validation errors without rejected input values."""

    cause = getattr(exc, "__cause__", None)
    error_reader = getattr(cause, "errors", None) or getattr(exc, "errors", None)
    if callable(error_reader):
        try:
            errors = error_reader(
                include_url=False,
                include_context=False,
                include_input=False,
            )
            details = []
            for item in errors:
                location = ".".join(str(part) for part in item.get("loc", ())) or "document"
                details.append(f"{location}: {item.get('msg', 'invalid value')}")
            if details:
                return "; ".join(details)
        except (TypeError, ValueError):
            pass
    return str(exc).splitlines()[0]


def _replace_engagement_targets(
    engagement: Engagement,
    domain: str,
    targets: Path,
) -> Engagement | None:
    """Validate target edits through the full engagement policy model."""

    payload = engagement.model_dump(mode="python")
    payload["web_targets" if domain == "web" else "network_targets"] = _target_values(targets)
    try:
        return Engagement.model_validate(payload)
    except ValueError as exc:
        _message(
            "[red]Targets were not saved:[/red] "
            f"{_engagement_error_summary(exc)}\n\n"
            "[dim]The existing engagement was left unchanged.[/dim]"
        )
        return None


def _select_engagement() -> tuple[Path, Engagement] | None:
    entries = []
    for path in _engagement_files():
        try:
            engagement = load_engagement(path)
            description = (
                f"{engagement.engagement_type.replace('_', ' ')}  •  "
                f"{engagement.mode}  •  "
                f"{len(engagement.scope.allow_hosts) + len(engagement.scope.allow_networks)} scope rule(s)"
            )
            entries.append((path, engagement, description))
        except EngagementError as exc:
            entries.append((path, None, f"invalid: {_engagement_error_summary(exc)}"))
    if not entries:
        _message("[yellow]No saved engagements were found. Create one first.[/yellow]")
        return None
    options = [MenuOption(path.stem, description) for path, _, description in entries]
    options.append(MenuOption("Back", "Return to engagement options"))
    choice = _choose("Select an engagement", options)
    if choice == len(entries):
        return None
    path, engagement, _ = entries[choice]
    if engagement is None:
        _message(f"[red]Cannot use invalid engagement file:[/red] {path}")
        return None
    return path.resolve(), engagement


def _collect_engagement(existing: Engagement | None = None) -> Engagement | None:
    name = _ask("Engagement name", default=existing.name if existing else "").strip()
    if not name:
        _message("[yellow]Engagement creation cancelled: a name is required.[/yellow]")
        return None

    type_options = ["bug_bounty", "client", "internal", "lab"]
    current_type = type_options.index(existing.engagement_type) if existing else 0
    type_choice = _choose(
        "Engagement type",
        [
            MenuOption("Bug bounty", "Public or private vulnerability disclosure program"),
            MenuOption("Client", "External authorized customer assessment"),
            MenuOption("Internal", "Company-owned environment"),
            MenuOption("Lab", "Local or isolated training environment"),
            MenuOption("Cancel"),
        ],
    )
    if type_choice == 4:
        return None
    engagement_type = type_options[type_choice]

    mode_choice = _choose(
        "Default assessment mode",
        [
            MenuOption("Safe", "Low traffic and conservative checks"),
            MenuOption("Standard", "Balanced daily assessment"),
            MenuOption("Deep", "Explicitly authorized comprehensive testing"),
            MenuOption("Cancel"),
        ],
    )
    if mode_choice == 3:
        return None
    mode = ["safe", "standard", "deep"][mode_choice]

    prior_scope = existing.scope if existing else EngagementScope(allow_hosts=["example.com"])
    allow_hosts = _csv_values("Allowed hosts (comma separated)", prior_scope.allow_hosts if existing else [])
    allow_networks = _csv_values("Allowed IPs/CIDRs (comma separated)", prior_scope.allow_networks)
    deny_hosts = _csv_values("Denied hosts (comma separated)", prior_scope.deny_hosts)
    deny_networks = _csv_values("Denied IPs/CIDRs (comma separated)", prior_scope.deny_networks)
    allow_ports = _csv_values("Allowed ports (comma separated; blank means unspecified)", prior_scope.allow_ports)
    deny_ports = _csv_values("Denied ports (comma separated)", prior_scope.deny_ports)
    exclude_paths = _csv_values("Excluded paths (comma separated)", prior_scope.exclude_paths)
    web_targets = _csv_values(
        "Saved web targets (comma separated; blank if none)",
        existing.web_targets if existing else [],
    )
    network_targets = _csv_values(
        "Saved network targets (comma separated; blank if none)",
        existing.network_targets if existing else [],
    )

    prior_traffic = existing.traffic if existing else TrafficPolicy()
    console.print()
    automation_allowed = Confirm.ask(
        "The written engagement rules allow automated testing",
        default=prior_traffic.automation_allowed,
    )
    rate = _optional_rate(prior_traffic.max_requests_per_second)
    user_agent = _ask(
        "Required user agent (blank if none)",
        default=prior_traffic.user_agent or "",
    ).strip() or None
    headers = dict(prior_traffic.headers)
    if headers:
        console.print()
        keep_headers = Confirm.ask(
            f"Keep {len(headers)} existing required header(s): {', '.join(sorted(headers))}",
            default=True,
        )
        if not keep_headers:
            headers = {}
    while True:
        header_name = _ask("Add required header name (blank to finish)", default="").strip()
        if not header_name:
            break
        headers[header_name] = _ask(f"Value for {header_name}").strip()
    notes = _ask("Notes (blank if none)", default=existing.notes or "" if existing else "").strip() or None

    try:
        return Engagement.model_validate({
            "schema_version": 1,
            "name": name,
            "engagement_type": engagement_type,
            "mode": mode,
            "scope": {
                "allow_hosts": allow_hosts,
                "deny_hosts": deny_hosts,
                "allow_networks": allow_networks,
                "deny_networks": deny_networks,
                "allow_ports": [int(value) for value in allow_ports],
                "deny_ports": [int(value) for value in deny_ports],
                "exclude_paths": exclude_paths,
            },
            "traffic": {
                "automation_allowed": automation_allowed,
                "max_requests_per_second": rate,
                "user_agent": user_agent,
                "headers": headers,
            },
            "web_targets": web_targets,
            "network_targets": network_targets,
            "notes": notes,
        })
    except (ValueError, TypeError) as exc:
        _message(
            "[red]Engagement validation failed:[/red] "
            f"{_engagement_error_summary(exc)}"
        )
        return None


def _engagement_panel(
    path: Path,
    engagement: Engagement,
    *,
    title: str = "Engagement review",
) -> Panel:
    summary = Table.grid(padding=(0, 1))
    summary.add_column(width=19, justify="right", style="bold")
    summary.add_column(overflow="fold")
    web_blockers = _web_engagement_blockers(engagement)
    network_ready = engagement.traffic.automation_allowed
    rows = [
        ("Name", engagement.name),
        ("Type", engagement.engagement_type.replace("_", " ").title()),
        ("Default mode", engagement.mode.title()),
        ("Automation", "Allowed" if engagement.traffic.automation_allowed else "Not allowed"),
        ("Rate ceiling", str(engagement.traffic.max_requests_per_second or "Mode default")),
        ("Allowed hosts", ", ".join(engagement.scope.allow_hosts) or "—"),
        ("Allowed networks", ", ".join(engagement.scope.allow_networks) or "—"),
        ("Denied hosts", ", ".join(engagement.scope.deny_hosts) or "—"),
        ("Denied networks", ", ".join(engagement.scope.deny_networks) or "—"),
        ("Allowed ports", ", ".join(map(str, engagement.scope.allow_ports)) or "Unspecified"),
        ("Denied ports", ", ".join(map(str, engagement.scope.deny_ports)) or "—"),
        ("Excluded paths", ", ".join(engagement.scope.exclude_paths) or "—"),
        ("Web targets", ", ".join(engagement.web_targets) or "—"),
        ("Network targets", ", ".join(engagement.network_targets) or "—"),
        ("User agent", "Configured" if engagement.traffic.user_agent else "—"),
        ("Headers", ", ".join(sorted(engagement.traffic.headers)) or "—"),
        (
            "Web readiness",
            "Ready" if not web_blockers else "Blocked: " + ", ".join(web_blockers),
        ),
        (
            "Network readiness",
            "Ready" if network_ready else "Blocked: automation is not allowed",
        ),
        ("File", str(path)),
    ]
    for label, value in rows:
        summary.add_row(f"{label}:", value)
    if engagement.notes:
        summary.add_row("Notes:", engagement.notes)
    return Panel(summary, title=title, border_style="cyan")


def _select_existing_network_run() -> tuple[Path, Path] | None:
    runs = []
    for path in sorted((Path.cwd() / "outputs").glob("run_*"), reverse=True):
        state_file = path / "state.json"
        targets = path / "work" / "input.network-targets.txt"
        if not state_file.is_file() or not targets.is_file():
            continue
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if state.get("domain") == "network" and state.get("status") in {
            "initialized", "running", "failed", "interrupted", "collected", "processing_failed"
        }:
            runs.append((path, targets, state))
    if not runs:
        _message("[yellow]No initialized or incomplete network runs were found.[/yellow]")
        return None
    options = [
        MenuOption(
            run.name,
            f"{_run_display_date(run)}  •  {state.get('targets', {}).get('entries', 0)} target(s)",
        )
        for run, _, state in runs
    ]
    options.append(MenuOption("Back"))
    choice = _choose("Select a network run", options)
    if choice == len(runs):
        return None
    run, targets, _ = runs[choice]
    return run.resolve(), targets.resolve()


def _network_assessment(
    engagement_file: Path,
    engagement: Engagement,
    resume_selection: tuple[Path, Path] | None = None,
) -> None:
    if resume_selection is not None:
        action = 2
        plan_only = False
        resume, targets = resume_selection
    else:
        action = _choose(
            f"Network assessment — {engagement.mode.title()} profile from engagement",
            [
                MenuOption("Run new assessment", "Review the plan, then execute authorized targets"),
                MenuOption("Review and save plan only", "Persist the exact plan without sending packets"),
                MenuOption("Resume assessment", "Continue an unfinished network run"),
                MenuOption("Back"),
            ],
        )
        if action == 3:
            return
        plan_only = action == 1
        resume = None
        if action == 2:
            selected = _select_existing_network_run()
            if selected is None:
                return
            resume, targets = selected
        else:
            if engagement.network_targets:
                target_action = _choose(
                    "Engagement network targets",
                    [
                        MenuOption(
                            f"Use saved targets ({len(engagement.network_targets)})",
                            "Use the targets recorded in this engagement (recommended)",
                        ),
                        MenuOption("Edit saved targets", "Replace reusable network targets"),
                        MenuOption("Override for this run", "Do not change the engagement"),
                        MenuOption("Back"),
                    ],
                )
                if target_action == 3:
                    return
                if target_action == 0:
                    targets = _engagement_targets_file(engagement, "network")
                elif target_action == 1:
                    targets = _direct_network_targets_file()
                    updated = _replace_engagement_targets(engagement, "network", targets)
                    if updated is None:
                        return
                    engagement = updated
                    save_engagement(engagement, engagement_file)
                    targets = _engagement_targets_file(engagement, "network")
                    _message("[green]✓ Saved engagement network targets updated.[/green]")
                else:
                    targets = _direct_network_targets_file()
            else:
                target_action = _choose(
                    "Engagement network targets",
                    [
                        MenuOption("Save targets to engagement", "Enter reusable network targets (recommended)"),
                        MenuOption("Override for this run", "Run without changing the engagement"),
                        MenuOption("Back"),
                    ],
                )
                if target_action == 2:
                    return
                targets = _direct_network_targets_file()
                if target_action == 0:
                    updated = _replace_engagement_targets(engagement, "network", targets)
                    if updated is None:
                        return
                    engagement = updated
                    save_engagement(engagement, engagement_file)
                    targets = _engagement_targets_file(engagement, "network")
                    _message("[green]✓ Saved engagement network targets updated.[/green]")
    try:
        parsed = parse_network_targets(targets)
    except NetworkTargetError as exc:
        _message(f"[red]{exc}[/red]")
        return
    mode = NetworkScanMode(engagement.mode)
    try:
        plan = build_nmap_plan(engagement, mode)
    except NetworkPolicyError as exc:
        _message(f"[red]Network policy cannot be planned:[/red] {exc}")
        return
    ports = (
        ", ".join(str(port) for port in plan.effective_ports)
        if plan.effective_ports
        else "Profile default"
    )
    command = [
        "deadbolt", "network", str(targets), "--engagement", str(engagement_file),
        "--mode", mode.value,
    ]
    details = [
        ("Engagement", engagement.name),
        ("Profile", f"{mode.value.title()} — inherited from engagement"),
        ("Policy", MODE_DESCRIPTIONS[mode]),
        ("Nmap phases", ", ".join(phase.name for phase in plan.phases)),
        ("Authorized ports", ports),
        ("Packet-rate ceiling", f"{plan.max_rate:g}/second"),
        ("Targets", f"{len(parsed.values)} entries representing {parsed.address_count} address(es)"),
        (
            "Execution",
            "Save immutable plan only; no packets will be sent"
            if plan_only else "Run unfinished Nmap phases and preserve resumable state",
        ),
    ]
    if resume:
        command.extend(["--resume-from", str(resume)])
        details.append(("Resume from", str(resume)))
    if plan_only:
        command.append("--plan-only")
    if not _preview(
        assessment="Network plan" if plan_only else "Network",
        target=targets,
        command=command,
        details=details,
        start_prompt="Save this plan now?" if plan_only else "Start assessment now?",
    ):
        return
    try:
        def show_progress(phase: str, event: str) -> None:
            if event in {"started", "complete", "cached", "failed"}:
                console.print(f"[cyan]nmap/{phase}[/cyan]  {event}")
            elif "Stats:" in event or "% done" in event:
                console.print(f"[dim]nmap/{phase}  {event.strip()}[/dim]")

        summary = run_network(
            targets,
            engagement_file,
            mode=mode,
            resume_from=resume,
            execute=not plan_only,
            progress=show_progress,
        )
        if plan_only:
            _message(
                f"[green]Network plan saved:[/green] {summary.run_dir / 'work' / 'nmap-plan.json'}\n"
                "[dim]No packets were sent.[/dim]"
            )
        else:
            report_lines = []
            for label, name in (
                ("Technical report", "technical-report.html"),
                ("Stakeholder report", "stakeholder-report.html"),
            ):
                report = summary.run_dir / name
                if report.is_file():
                    report_lines.append(f"[cyan]{label}:[/cyan] {report}")
            reports = "\n" + "\n".join(report_lines) if report_lines else ""
            _message(
                f"[green]Network assessment {summary.status}:[/green] {summary.run_dir}\n"
                f"[dim]{summary.completed_phases} phase(s) complete; "
                f"{summary.cached_phases} restored from resume.[/dim]"
                f"{reports}"
            )
    except (NetworkExecutionCancelled, EngagementError, NetworkTargetError, RuntimeError, ValueError) as exc:
        _message(f"[red]{exc}[/red]")


def _start_from_engagement(path: Path, engagement: Engagement) -> None:
    if not _automation_allowed(engagement):
        return
    choice = _choose(
        "Assessment type",
        [
            MenuOption("Web application", "Use engagement scope and default mode"),
            MenuOption("Network", "Plan, run, or resume a scope-bound network assessment"),
            MenuOption("Android application", "Static analysis of an APK"),
            MenuOption("iOS application", "Static analysis of an IPA"),
            MenuOption("Back"),
        ],
    )
    if choice == 0:
        _start_engagement_web(path, engagement)
    elif choice == 1:
        _start_engagement_network(path, engagement)
    elif choice == 2:
        _mobile_assessment("Android")
    elif choice == 3:
        _mobile_assessment("iOS")


def _validate_saved_engagements() -> None:
    files = _engagement_files()
    if not files:
        _message("[yellow]No saved engagements were found.[/yellow]")
        return
    table = Table(title="Saved Engagement Validation")
    table.add_column("File", style="bold cyan")
    table.add_column("Status")
    table.add_column("Summary", overflow="fold")
    valid = warnings = invalid = 0
    for path in files:
        try:
            engagement = load_engagement(path)
            permissions = path.stat().st_mode & 0o777
            permission_ok = permissions == 0o600
            if permission_ok:
                status = "[green]valid[/green]"
                valid += 1
            else:
                status = "[yellow]warning[/yellow]"
                warnings += 1
            scope_rules = len(engagement.scope.allow_hosts) + len(engagement.scope.allow_networks)
            detail = (
                f"{engagement.engagement_type.replace('_', ' ')}  •  {engagement.mode}  •  "
                f"{scope_rules} authorized scope rule(s)  •  "
                f"automation {'allowed' if engagement.traffic.automation_allowed else 'blocked'}"
            )
            if not permission_ok:
                detail = f"permissions {permissions:03o}; expected 600  •  " + detail
        except (EngagementError, OSError) as exc:
            status = "[red]invalid[/red]"
            detail = _engagement_error_summary(exc)
            invalid += 1
        table.add_row(path.name, status, detail)
    console.print()
    console.print(table)
    console.print()
    console.print(
        f"[bold]Validation summary:[/bold] [green]{valid} valid[/green]  •  "
        f"[yellow]{warnings} warning(s)[/yellow]  •  [red]{invalid} invalid[/red]"
    )
    console.print()


def _workspace_scope_panel(path: Path) -> Panel:
    try:
        scope = load_scope(path)
        if not isinstance(scope, dict):
            raise ValueError("scope document must be a YAML mapping")
        allowed = scope.get("allow", [])
        denied = scope.get("deny", [])
        if not isinstance(allowed, list) or not isinstance(denied, list):
            raise ValueError("scope.allow and scope.deny must be lists")
        status = "Valid explicit allowlist" if allowed else "Unsafe: allowlist is empty"
        border = "cyan" if allowed else "red"
        rows = [
            ("Status", status),
            ("Allowed", ", ".join(map(str, allowed)) or "—"),
            ("Denied", ", ".join(map(str, denied)) or "—"),
            ("File", str(path)),
        ]
    except (OSError, ValueError, yaml.YAMLError) as exc:
        border = "red"
        rows = [("Status", f"Invalid: {exc}"), ("File", str(path))]
    summary = Table.grid(padding=(0, 1))
    summary.add_column(width=10, justify="right", style="bold")
    summary.add_column(overflow="fold")
    for label, value in rows:
        summary.add_row(f"{label}:", value)
    return Panel(summary, title="Workspace web scope", border_style=border)


def _review_workspace_scope() -> None:
    path = (Path.cwd() / "scope.yaml").resolve()
    console.print()
    console.print(_workspace_scope_panel(path))
    console.print()
    console.print(
        "[dim]scope.yaml is supported for existing web workflows. Saved engagements "
        "provide the stronger cross-domain authorization model.[/dim]"
    )
    console.print()


def _manage_engagement(path: Path, engagement: Engagement) -> None:
    while True:
        console.print()
        console.print(_engagement_panel(path, engagement))
        choice = _choose(
            "Engagement actions",
            [
                MenuOption("Start assessment", "Use this authorization context"),
                MenuOption("Edit", "Review and replace fields safely"),
                MenuOption("Back", "Return to engagements"),
            ],
        )
        if choice == 0:
            _start_from_engagement(path, engagement)
        elif choice == 1:
            updated = _collect_engagement(engagement)
            if updated is None:
                continue
            if not _confirm_engagement_save(path, updated, "Save these engagement changes?"):
                continue
            saved = save_engagement(updated, path)
            path, engagement = saved, updated
            _message(f"[green]Engagement updated:[/green] {path}")
        else:
            return


def _engagements_menu() -> None:
    while True:
        choice = _choose(
            "Engagements and scope",
            [
                MenuOption("Create engagement", "Record authorization, scope, and traffic policy"),
                MenuOption("Browse engagements", "Review, edit, or start an assessment"),
                MenuOption("Validate saved engagements", "Check schema, scope, automation, and file permissions"),
                MenuOption("Review workspace scope.yaml", "Inspect existing web allow and deny rules"),
                MenuOption("Back", "Return to the main menu"),
            ],
        )
        if choice == 0:
            engagement = _collect_engagement()
            if engagement is None:
                continue
            path = engagement_path(engagement.name)
            if path.exists():
                _message(f"[red]An engagement already exists at:[/red] {path}")
                continue
            if not _confirm_engagement_save(path, engagement, "Save this engagement?"):
                continue
            saved = save_engagement(engagement, path)
            _message(f"[green]Engagement created:[/green] {saved}")
            _manage_engagement(saved, engagement)
        elif choice == 1:
            selected = _select_engagement()
            if selected:
                _manage_engagement(*selected)
        elif choice == 2:
            _validate_saved_engagements()
        elif choice == 3:
            _review_workspace_scope()
        else:
            return


def _tool_command_panel(title: str, description: str, command: list[str]) -> None:
    """Teach the canonical command before a guided lifecycle action."""

    body = Group(
        Text(description),
        Text(),
        Text("Equivalent command:", style="bold"),
        Text(),
        Text(shlex.join(command), style="cyan"),
    )
    console.print()
    console.print(Panel(body, title=title, border_style="cyan"))
    console.print()


def _run_tool_command(
    *,
    title: str,
    description: str,
    command: list[str],
    action: Callable[[], None],
    confirmation: str | None = None,
) -> bool:
    """Preview and execute one lifecycle command without exiting Guided Mode."""

    _tool_command_panel(title, description, command)
    if confirmation and not Confirm.ask(confirmation, default=False):
        _message("[yellow]Tool action cancelled.[/yellow]")
        return False
    if confirmation:
        console.print()
    try:
        action()
        return True
    except Exit as exc:
        if exc.exit_code:
            _message(
                "[yellow]The command completed with issues. Review the result above; "
                "Guided Mode is still available.[/yellow]"
            )
        return False
    except ClickException as exc:
        _message(f"[red]{exc.format_message()}[/red]")
        return False
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        _message(f"[red]Tool action failed:[/red] {exc}")
        return False


def _select_scanner(
    title: str,
    *,
    names: list[str] | None = None,
    annotations: dict[str, str] | None = None,
) -> ToolConfig | None:
    manifest = load_tool_manifest()
    allowed = set(names) if names is not None else None
    configs = [
        config for config in manifest.tools.values()
        if allowed is None or config.name in allowed
    ]
    if not configs:
        _message("[yellow]No matching scanner tools are available.[/yellow]")
        return None
    notes = annotations or {}
    options = []
    for config in configs:
        ownership = "managed build" if config.managed else "external image"
        detail = f"{', '.join(config.domains)}  •  {config.display_version}  •  {ownership}"
        if notes.get(config.name):
            detail += f"  •  {notes[config.name]}"
        options.append(MenuOption(config.name, detail))
    options.append(MenuOption("Back", "Return to the previous menu"))
    choice = _choose(title, options)
    return None if choice == len(configs) else configs[choice]


def _build_preferences(*, multiple: bool) -> tuple[bool, bool, int] | None:
    behavior = _choose(
        "Build behavior",
        [
            MenuOption("Use cache", "Fast deterministic rebuild (recommended)"),
            MenuOption("Refresh base images", "Use cache but pull newer base layers"),
            MenuOption("Clean rebuild", "Disable cache and refresh base layers"),
            MenuOption("Back", "Return without building"),
        ],
    )
    if behavior == 3:
        return None
    workers = 1
    if multiple:
        parallel = _choose(
            "Build concurrency",
            [
                MenuOption("Balanced", "3 simultaneous Docker operations"),
                MenuOption("Conservative", "1 operation at a time"),
                MenuOption("Fast", "5 simultaneous Docker operations"),
                MenuOption("Back", "Return without building"),
            ],
        )
        if parallel == 3:
            return None
        workers = [3, 1, 5][parallel]
    return behavior == 2, behavior in {1, 2}, workers


def _guided_build(*, tools: list[str] | None = None, domain: str | None = None, outdated: bool = False) -> None:
    preferences = _build_preferences(multiple=tools is None or len(tools) != 1)
    if preferences is None:
        return
    no_cache, pull, workers = preferences
    command = ["deadbolt", "tools", "build"]
    for name in tools or []:
        command.extend(["--tool", name])
    if domain:
        command.extend(["--domain", domain])
    if outdated:
        command.append("--outdated")
    command.extend(["--parallel", str(workers)])
    if no_cache:
        command.append("--no-cache")
    if pull:
        command.append("--pull")
    scope = (
        f"the {tools[0]} image" if tools and len(tools) == 1
        else f"all {domain} scanner images" if domain
        else "missing or mismatched scanner images" if outdated
        else "all configured scanner images"
    )
    _run_tool_command(
        title="Build scanner images",
        description=f"Build or pull {scope}, then verify every installed version.",
        command=command,
        confirmation="Start this Docker build now?",
        action=lambda: tool_build_command(
            tools=tools,
            domains=[domain] if domain else None,
            outdated=outdated,
            parallel=workers,
            no_cache=no_cache,
            pull=pull,
            as_json=False,
        ),
    )


def _tool_build_menu() -> None:
    while True:
        choice = _choose(
            "Build and repair scanner images",
            [
                MenuOption("Repair unhealthy images", "Only missing, mismatched, or unverifiable tools"),
                MenuOption("Build one scanner", "Rebuild or pull an individual tool"),
                MenuOption("Build a scanner category", "Web, network, Android, or iOS"),
                MenuOption("Build every scanner", "Recreate the full configured toolset"),
                MenuOption("Back", "Return to scanner tools"),
            ],
        )
        if choice == 0:
            _guided_build(outdated=True)
        elif choice == 1:
            tool = _select_scanner("Select a scanner to build")
            if tool:
                _guided_build(tools=[tool.name])
        elif choice == 2:
            category = _choose(
                "Select scanner category",
                [
                    MenuOption("Web", "Web application discovery and testing"),
                    MenuOption("Network", "Network discovery and service analysis"),
                    MenuOption("Android", "Android application analysis"),
                    MenuOption("iOS", "iOS application analysis"),
                    MenuOption("Back"),
                ],
            )
            if category < 4:
                _guided_build(domain=["web", "network", "android", "ios"][category])
        elif choice == 3:
            _guided_build()
        else:
            return


def _choose_upgrade_scope(title: str) -> list[str] | None | bool:
    choice = _choose(
        title,
        [
            MenuOption("All scanners", "Check every configured tool"),
            MenuOption("One scanner", "Choose an individual tool"),
            MenuOption("Back", "Return to upgrade management"),
        ],
    )
    if choice == 0:
        return []
    if choice == 1:
        selected = _select_scanner("Select a scanner")
        return [selected.name] if selected else False
    return False


def _upgrade_state() -> dict:
    path = Path.cwd() / ".deadbolt" / "tool-upgrades.json"
    if not path.is_file():
        return {"candidates": {}, "rollbacks": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {"candidates": {}, "rollbacks": {}}
    except (OSError, ValueError, json.JSONDecodeError):
        return {"candidates": {}, "rollbacks": {}}


def _state_scanner(section: str, title: str) -> ToolConfig | None:
    records = _upgrade_state().get(section, {})
    manifest = load_tool_manifest()
    names = [name for name in manifest.tools if name in records]
    annotations = {}
    for name in names:
        record = records[name]
        if section == "candidates" and record.get("verified"):
            annotations[name] = f"verified candidate {record.get('to', '—')}"
        elif section == "rollbacks":
            annotations[name] = f"rollback available: {record.get('version', '—')}"
    names = [
        name for name in names
        if section != "candidates" or records[name].get("verified")
    ]
    if not names:
        noun = "verified candidates" if section == "candidates" else "recorded rollbacks"
        _message(f"[yellow]There are no {noun} available.[/yellow]")
        return None
    return _select_scanner(title, names=names, annotations=annotations)


def _tool_upgrade_menu() -> None:
    while True:
        choice = _choose(
            "Upgrade scanner tools",
            [
                MenuOption("Check for upgrades", "Read-only comparison with upstream releases"),
                MenuOption("Test candidate upgrades", "Build in isolation and verify versions"),
                MenuOption("Promote a verified candidate", "Make a tested version active and retain rollback"),
                MenuOption("Roll back a scanner", "Restore the previously retained version"),
                MenuOption("Back", "Return to scanner tools"),
            ],
        )
        if choice in {0, 1}:
            names = _choose_upgrade_scope(
                "Upgrade check scope" if choice == 0 else "Candidate test scope"
            )
            if names is False:
                continue
            command = ["deadbolt", "tools", "upgrade", "plan" if choice == 0 else "test"]
            for name in names:
                command.extend(["--tool", name])
            if choice == 0:
                _run_tool_command(
                    title="Upgrade plan",
                    description="Compare current manifest pins with upstream versions without changing anything.",
                    command=command,
                    action=lambda selected=names: tool_upgrade_plan_command(
                        tools=selected or None, as_json=False
                    ),
                )
            else:
                _run_tool_command(
                    title="Test upgrade candidates",
                    description="Build isolated candidate images and record only versions that pass verification.",
                    command=command,
                    confirmation="Build and test these candidate upgrades now?",
                    action=lambda selected=names: tool_upgrade_test_command(
                        tools=selected or None,
                        no_cache=False,
                        verbose=False,
                        as_json=False,
                    ),
                )
        elif choice == 2:
            tool = _state_scanner("candidates", "Select a verified candidate")
            if tool:
                command = ["deadbolt", "tools", "upgrade", "promote", "--tool", tool.name]
                _run_tool_command(
                    title="Promote verified candidate",
                    description="Activate the verified image, update the manifest pin, and preserve the current image for rollback.",
                    command=command,
                    confirmation=f"Promote the verified {tool.name} candidate now?",
                    action=lambda: tool_upgrade_promote_command(tool=tool.name, verbose=False),
                )
        elif choice == 3:
            tool = _state_scanner("rollbacks", "Select a scanner to roll back")
            if tool:
                command = ["deadbolt", "tools", "upgrade", "rollback", "--tool", tool.name]
                _run_tool_command(
                    title="Roll back scanner",
                    description="Restore the retained image and previous manifest version for this scanner.",
                    command=command,
                    confirmation=f"Roll back {tool.name} now?",
                    action=lambda: tool_upgrade_rollback_command(tool=tool.name, verbose=False),
                )
        else:
            return


def _tool_status_menu() -> None:
    while True:
        choice = _choose(
            "Scanner version status",
            [
                MenuOption("Check installed and upstream", "Detect available releases; internet required"),
                MenuOption("Check installed images only", "Fast offline verification against manifest pins"),
                MenuOption("Back", "Return to scanner tools"),
            ],
        )
        if choice == 2:
            return
        offline = choice == 1
        command = ["deadbolt", "tools", "status"] + (["--offline"] if offline else [])
        _run_tool_command(
            title="Scanner status",
            description=(
                "Verify installed Docker images against Deadbolt's configured versions."
                if offline else
                "Compare configured and installed versions with current upstream releases."
            ),
            command=command,
            action=lambda selected=offline: tool_status_command(
                as_json=False, offline=selected, workers=4, domains=None
            ),
        )


def _tool_cleanup_menu() -> None:
    while True:
        choice = _choose(
            "Scanner image cleanup",
            [
                MenuOption("Review cleanup plan", "Find obsolete Deadbolt tags without deleting anything"),
                MenuOption("Back", "Return to scanner tools"),
            ],
        )
        if choice == 1:
            return
        shown = _run_tool_command(
            title="Deadbolt image cleanup",
            description="Inspect only Deadbolt-owned images. Active, candidate, and rollback references remain protected.",
            command=["deadbolt", "tools", "cleanup"],
            action=lambda: tool_cleanup_command(apply=False, as_json=False),
        )
        if not shown:
            continue
        console.print()
        if not Confirm.ask("Apply the displayed cleanup plan now?", default=False):
            _message("[dim]Cleanup plan left unchanged.[/dim]")
            continue
        _run_tool_command(
            title="Apply Deadbolt image cleanup",
            description="Revalidate the safe plan, then remove only the obsolete references it contains.",
            command=["deadbolt", "tools", "cleanup", "--apply"],
            action=lambda: tool_cleanup_command(apply=True, as_json=False),
        )


def _scanner_tools_menu() -> None:
    while True:
        choice = _choose(
            "Scanner tools",
            [
                MenuOption("Version status", "Configured, installed, and upstream versions"),
                MenuOption("Build and repair images", "Repair one, a category, or the complete toolset"),
                MenuOption("Upgrade management", "Plan, test, promote, and roll back safely"),
                MenuOption("Clean obsolete images", "Preview conservative Deadbolt-only cleanup"),
                MenuOption("Back", "Return to the main menu"),
            ],
        )
        if choice == 0:
            _tool_status_menu()
        elif choice == 1:
            _tool_build_menu()
        elif choice == 2:
            _tool_upgrade_menu()
        elif choice == 3:
            _tool_cleanup_menu()
        else:
            return


def _read_run_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _infer_run_domain(run: Path, meta: dict, state: dict) -> str:
    recorded = str(meta.get("domain") or state.get("domain") or "").lower()
    if recorded in {"web", "network", "android", "ios"}:
        return recorded
    tools = set((state.get("tools") or {}).keys())
    if tools.intersection({"subfinder", "dnsx", "httpx", "katana", "nuclei"}):
        return "web"
    if tools.intersection({"apktool", "jadx", "androguard"}):
        return "android"
    if (run / "work" / "input.network-targets.txt").is_file():
        return "network"
    return "unknown"


def _run_findings_count(run: Path) -> int | None:
    path = run / "normalized" / "findings.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        return len(payload["findings"])
    return None


def _assessment_run(run: Path) -> AssessmentRun | None:
    meta = _read_run_json(run / "meta.json")
    state = _read_run_json(run / "state.json")
    if not meta and not state:
        return None
    domain = _infer_run_domain(run, meta, state)
    errors = len(meta.get("errors") or {})
    tool_states = [
        str(item.get("status", ""))
        for item in (state.get("tools") or {}).values()
        if isinstance(item, dict)
    ]
    has_failed_tool = any(value in {"failed", "interrupted", "processing_failed"} for value in tool_states)
    recorded_status = str(meta.get("status") or state.get("status") or "").lower()
    if recorded_status in {"complete", "completed"}:
        status = "complete with issues" if errors or has_failed_tool else "complete"
    elif recorded_status:
        status = recorded_status.replace("_", " ")
    elif meta.get("finished_at"):
        status = "complete with issues" if errors or has_failed_tool else "complete"
    elif has_failed_tool:
        status = "failed"
    else:
        status = "interrupted"
    resumable = status != "complete" and domain in {"web", "network", "android", "ios"}
    profile = str(
        meta.get("scan_profile")
        or (state.get("run") or {}).get("scan_profile")
        or (state.get("run") or {}).get("mode")
        or "—"
    )
    return AssessmentRun(
        path=run.resolve(),
        domain=domain,
        status=status,
        profile=profile,
        started=_run_display_date(run),
        findings=_run_findings_count(run),
        errors=max(errors, sum(value == "failed" for value in tool_states)),
        resumable=resumable,
        meta=meta,
        state=state,
    )


def _assessment_runs(*, resumable_only: bool = False) -> list[AssessmentRun]:
    outputs = Path.cwd() / "outputs"
    records = []
    for path in sorted(outputs.glob("run_*"), key=lambda item: item.name, reverse=True):
        if not path.is_dir():
            continue
        record = _assessment_run(path)
        if record and (not resumable_only or record.resumable):
            records.append(record)
    return records


def _run_input(record: AssessmentRun) -> Path | None:
    if record.domain == "web":
        return _recover_run_targets(record.path)
    if record.domain == "network":
        candidate = record.path / "work" / "input.network-targets.txt"
        return candidate.resolve() if candidate.is_file() else None
    raw = record.meta.get("targets_file")
    if raw:
        candidate = Path(str(raw)).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        if candidate.is_file():
            return candidate.resolve()
    return None


def _run_reports(record: AssessmentRun) -> list[tuple[str, Path]]:
    reports = []
    for label, name in (
        ("Technical report", "technical-report.html"),
        ("Stakeholder report", "stakeholder-report.html"),
    ):
        path = record.path / name
        if path.is_file():
            reports.append((label, path.resolve()))
    return reports


def _run_review_panel(record: AssessmentRun) -> Panel:
    target = _run_input(record)
    reports = _run_reports(record)
    summary = Table.grid(padding=(0, 1))
    summary.add_column(width=13, justify="right", style="bold")
    summary.add_column(overflow="fold")
    summary.add_row("Run ID:", record.path.name)
    summary.add_row("Assessment:", record.domain.title())
    summary.add_row("Started:", record.started)
    summary.add_row("Status:", record.status.title())
    summary.add_row("Profile:", record.profile)
    summary.add_row("Input:", str(target) if target else "Unavailable")
    summary.add_row("Results:", str(record.findings) if record.findings is not None else "Unavailable")
    summary.add_row("Errors:", str(record.errors))
    summary.add_row("Reports:", str(len(reports)))
    summary.add_row("Run folder:", str(record.path))
    return Panel(summary, title="Assessment run", border_style="cyan")


def _run_report_menu(record: AssessmentRun) -> None:
    reports = _run_reports(record)
    if not reports:
        _message("[yellow]This run does not have generated reports yet.[/yellow]")
        return
    options = [MenuOption(label, str(path)) for label, path in reports]
    options.append(MenuOption("Back", "Return to run actions"))
    choice = _choose("Select a report", options)
    if choice == len(reports):
        return
    label, report = reports[choice]
    audience = "technical" if report.name.startswith("technical") else "stakeholder"
    _run_tool_command(
        title=f"Open {label.lower()}",
        description=f"Open the generated {audience} report for {record.path.name} in the default browser.",
        command=[
            "deadbolt", "reports", "open", str(record.path),
            "--audience", audience,
        ],
        confirmation="Open this report in the default browser?",
        action=lambda: open_report_command(
            run_dir=record.path,
            audience=audience,
        ),
    )


def _run_artifacts(record: AssessmentRun) -> None:
    rows = []
    for label, relative in (
        ("Run folder", "."),
        ("Metadata", "meta.json"),
        ("Resume state", "state.json"),
        ("Normalized data", "normalized"),
        ("Raw evidence", "raw"),
        ("Logs", "logs"),
        ("Working files", "work"),
        ("Scope snapshot", "scope"),
    ):
        path = record.path if relative == "." else record.path / relative
        if path.exists():
            rows.append((label, str(path.resolve())))
    table = Table(title="Assessment Artifacts")
    table.add_column("Artifact", style="bold cyan")
    table.add_column("Path")
    for row in rows:
        table.add_row(*row)
    console.print()
    console.print(table)
    console.print()


def _network_resume_context(record: AssessmentRun) -> tuple[Path, Engagement] | None:
    snapshot = (
        (record.state.get("engagement") or {}).get("snapshot")
        or record.meta.get("scope_snapshot")
    )
    if not snapshot:
        _message("[red]This network run has no preserved engagement snapshot.[/red]")
        return None
    path = Path(str(snapshot))
    path = path if path.is_absolute() else record.path / path
    try:
        return path.resolve(), load_engagement(path)
    except EngagementError as exc:
        _message(f"[red]The preserved engagement cannot be loaded:[/red] {exc}")
        return None


def _resume_mobile_run(record: AssessmentRun, artifact: Path) -> None:
    platform = "Android" if record.domain == "android" else "iOS"
    command = ["deadbolt", record.domain, str(artifact), "--output", str(record.path)]
    if not _preview(
        assessment=f"Resume {platform} application",
        target=artifact,
        command=command,
        details=[("Resume from", str(record.path))],
    ):
        return
    try:
        if record.domain == "android":
            run_android(apk_path=artifact, output_dir=record.path)
        else:
            run_ios(ipa_path=artifact, output_dir=record.path)
    except (OSError, RuntimeError, ValueError) as exc:
        _message(f"[red]{exc}[/red]")


def _resume_assessment_run(record: AssessmentRun) -> None:
    target = _run_input(record)
    if target is None:
        _message(
            "[red]Resume is unavailable because the original input cannot be recovered.[/red]"
        )
        return
    if record.domain == "web":
        _web_assessment(resume_selection=(record.path, target))
    elif record.domain == "network":
        context = _network_resume_context(record)
        if context:
            engagement_file, engagement = context
            _network_assessment(
                engagement_file,
                engagement,
                resume_selection=(record.path, target),
            )
    elif record.domain in {"android", "ios"}:
        _resume_mobile_run(record, target)


def _manage_assessment_run(record: AssessmentRun) -> None:
    while True:
        console.print()
        console.print(_run_review_panel(record))
        options = []
        if record.resumable:
            options.append(MenuOption("Resume assessment", "Continue failed or unfinished work"))
        options.extend([
            MenuOption("Reports", "View or open generated technical and stakeholder reports"),
            MenuOption("Artifacts", "Locate metadata, evidence, logs, and normalized data"),
            MenuOption("Back", "Return to assessment history"),
        ])
        choice = _choose("Run actions", options)
        offset = 0
        if record.resumable:
            if choice == 0:
                _resume_assessment_run(record)
                refreshed = _assessment_run(record.path)
                if refreshed:
                    record = refreshed
                continue
            offset = 1
        action = choice - offset
        if action == 0:
            _run_report_menu(record)
        elif action == 1:
            _run_artifacts(record)
        else:
            return


def _select_assessment_run(*, resumable_only: bool = False) -> AssessmentRun | None:
    runs = _assessment_runs(resumable_only=resumable_only)
    if not runs:
        qualifier = "resumable " if resumable_only else ""
        _message(f"[yellow]No {qualifier}assessment runs were found in outputs/.[/yellow]")
        return None
    options = []
    for record in runs:
        findings = f"{record.findings} result(s)" if record.findings is not None else "results unavailable"
        options.append(MenuOption(
            record.path.name,
            f"{record.started}  •  {record.domain}  •  {record.status}  •  {findings}",
        ))
    options.append(MenuOption("Back", "Return to previous assessments"))
    choice = _choose("Select an assessment run", options)
    return None if choice == len(runs) else runs[choice]


def _previous_assessments_menu() -> None:
    while True:
        choice = _choose(
            "Previous assessments",
            [
                MenuOption("Browse all runs", "Completed, failed, and interrupted assessments"),
                MenuOption("Runs requiring attention", "Only failed or resumable assessments"),
                MenuOption("Back", "Return to the main menu"),
            ],
        )
        if choice == 2:
            return
        selected = _select_assessment_run(resumable_only=choice == 1)
        if selected:
            _manage_assessment_run(selected)


def _report_generation_ready(record: AssessmentRun) -> bool:
    return (
        (record.path / "meta.json").is_file()
        and (record.path / "normalized" / "findings.json").is_file()
    )


def _report_runs(
    *,
    domain: str | None = None,
    generated_only: bool = True,
) -> list[AssessmentRun]:
    records = []
    for record in _assessment_runs():
        if domain and record.domain != domain:
            continue
        if generated_only and not _run_reports(record):
            continue
        if not generated_only and not _report_generation_ready(record):
            continue
        records.append(record)
    return records


def _select_report_run(
    *,
    title: str = "Select an assessment report",
    domain: str | None = None,
    generated_only: bool = True,
) -> AssessmentRun | None:
    records = _report_runs(domain=domain, generated_only=generated_only)
    if not records:
        qualifier = f" {domain}" if domain else ""
        noun = "generated reports" if generated_only else "report-ready runs"
        _message(f"[yellow]No{qualifier} {noun} were found in outputs/.[/yellow]")
        return None
    options = []
    for record in records:
        reports = _run_reports(record)
        available = ", ".join(label.removesuffix(" report") for label, _ in reports)
        if not available:
            available = "not generated"
        options.append(MenuOption(
            record.path.name,
            f"{record.started}  •  {record.domain}  •  {record.status}  •  {available}",
        ))
    options.append(MenuOption("Back", "Return to reports"))
    choice = _choose(title, options)
    return None if choice == len(records) else records[choice]


def _generate_run_reports(record: AssessmentRun) -> None:
    existing = len(_run_reports(record))
    description = (
        "Refresh both reports from preserved normalized evidence and current templates."
        if existing else
        "Generate technical and stakeholder reports from preserved normalized evidence."
    )
    completed = _run_tool_command(
        title="Refresh assessment reports" if existing else "Generate assessment reports",
        description=description,
        command=["deadbolt", "reports", "generate", str(record.path)],
        confirmation=(
            "Replace the existing generated reports now?"
            if existing else "Generate both reports now?"
        ),
        action=lambda: generate_report_command(run_dir=record.path),
    )
    if completed:
        _message(f"[green]Reports are ready:[/green] {record.path}")


def _manage_report_run(record: AssessmentRun) -> None:
    while True:
        console.print()
        console.print(_run_review_panel(record))
        choice = _choose(
            "Report actions",
            [
                MenuOption("Open a report", "Choose technical or stakeholder audience"),
                MenuOption("Generate or refresh both", "Rebuild reports from preserved evidence"),
                MenuOption("Back", "Return to the report library"),
            ],
        )
        if choice == 0:
            _run_report_menu(record)
        elif choice == 1:
            if _report_generation_ready(record):
                _generate_run_reports(record)
            else:
                _message(
                    "[yellow]Report generation requires meta.json and "
                    "normalized/findings.json.[/yellow]"
                )
        else:
            return


def _report_domain_filter() -> str | None | bool:
    choice = _choose(
        "Filter reports by assessment type",
        [
            MenuOption("Web", "Web application assessments"),
            MenuOption("Network", "Network assessments"),
            MenuOption("Android", "Android application assessments"),
            MenuOption("iOS", "iOS application assessments"),
            MenuOption("Back", "Return to reports"),
        ],
    )
    return False if choice == 4 else ["web", "network", "android", "ios"][choice]


def _reports_menu() -> None:
    while True:
        choice = _choose(
            "Reports",
            [
                MenuOption("Latest assessment reports", "Open the newest generated report set"),
                MenuOption("Browse report library", "All runs with generated reports"),
                MenuOption("Filter by assessment type", "Web, network, Android, or iOS"),
                MenuOption("Generate or refresh reports", "Use preserved evidence and current templates"),
                MenuOption("Back", "Return to the main menu"),
            ],
        )
        selected = None
        if choice == 0:
            records = _report_runs()
            if not records:
                _message("[yellow]No generated assessment reports were found.[/yellow]")
                continue
            selected = records[0]
        elif choice == 1:
            selected = _select_report_run()
        elif choice == 2:
            domain = _report_domain_filter()
            if domain is False:
                continue
            selected = _select_report_run(
                title=f"Select a {domain} assessment report",
                domain=domain,
            )
        elif choice == 3:
            selected = _select_report_run(
                title="Select a run to generate or refresh",
                generated_only=False,
            )
            if selected:
                _generate_run_reports(selected)
            continue
        else:
            return
        if selected:
            _manage_report_run(selected)


def _assessment_readiness() -> None:
    choice = _choose(
        "Assessment readiness",
        [
            MenuOption("Web", "Verify all web scanner images"),
            MenuOption("Network", "Verify the pinned network scanner image"),
            MenuOption("Android", "Verify Android analysis images"),
            MenuOption("iOS", "Verify iOS analysis images"),
            MenuOption("Back", "Return to environment health"),
        ],
    )
    if choice == 4:
        return
    domain = ["web", "network", "android", "ios"][choice]
    _run_tool_command(
        title=f"{domain.title()} assessment readiness",
        description=(
            f"Verify installed {domain} scanner images against Deadbolt's pinned manifest "
            "without contacting upstream services."
        ),
        command=[
            "deadbolt", "tools", "status", "--offline", "--domain", domain,
        ],
        action=lambda: tool_status_command(
            as_json=False,
            offline=True,
            workers=4,
            domains=[domain],
        ),
    )


def _environment_health_menu() -> None:
    while True:
        choice = _choose(
            "Environment health",
            [
                MenuOption("Complete readiness check", "Docker, images, scope, assets, reports, and integrations"),
                MenuOption("Readiness by assessment type", "Web, network, Android, or iOS scanner images"),
                MenuOption("Optional provider status", "Check .env integration names without exposing values"),
                MenuOption("Repair unhealthy images", "Build only missing, mismatched, or unverifiable scanners"),
                MenuOption("Back", "Return to the main menu"),
            ],
        )
        if choice == 0:
            _run_tool_command(
                title="Complete environment health",
                description="Run every non-destructive Deadbolt readiness check.",
                command=["deadbolt", "tools", "doctor"],
                action=lambda: tool_doctor_command(as_json=False),
            )
        elif choice == 1:
            _assessment_readiness()
        elif choice == 2:
            _run_tool_command(
                title="Optional provider status",
                description=(
                    "Show which optional integrations have all required variable names configured. "
                    "Secret values are never printed."
                ),
                command=["deadbolt", "tools", "providers"],
                action=lambda: tool_providers_command(as_json=False),
            )
        elif choice == 3:
            _guided_build(outdated=True)
        else:
            return


def run_wizard() -> None:
    """Run the interactive launcher until the user exits."""

    identity = Group(
        Text.from_markup(
            f"[bold bright_cyan]DEADBOLT[/bold bright_cyan] "
            f"[cyan]( GUIDED MODE )[/cyan] [dim]v{get_version()}[/dim]\n"
        ),
        Text.from_markup(f"[dim]Workspace[/dim]  {Path.cwd()}"),
        Rule(style="dim cyan"),
        Text(
            "Plan, verify, and run authorized security assessments.",
            style="dim",
        ),
    )
    console.print(
        Panel(identity, border_style="cyan", padding=(1, 2), width=76)
    )
    try:
        while True:
            choice = _choose(
                "Main menu",
                [
                    MenuOption("Start an assessment", "Web, mobile, and network assessments"),
                    MenuOption("Previous assessments", "Resume runs and inspect artifacts"),
                    MenuOption("Scanner tools", "Status, build, upgrade, and roll back"),
                    MenuOption("Reports", "Review generated assessment reports"),
                    MenuOption("Environment health", "Validate Docker, images, scope, and assets"),
                    MenuOption("Engagements and scope", "Authorization policies and workspace scope"),
                    MenuOption("Exit", "Leave guided mode"),
                ],
            )
            if choice == 0:
                _start_assessment()
            elif choice == 1:
                _previous_assessments_menu()
            elif choice == 2:
                _scanner_tools_menu()
            elif choice == 3:
                _reports_menu()
            elif choice == 4:
                _environment_health_menu()
            elif choice == 5:
                _engagements_menu()
            else:
                console.print("\n[dim]Goodbye! See you soon...[/dim]\n")
                return
    except (KeyboardInterrupt, EOFError):
        console.print("\n\n[dim]Goodbye! See you soon...[/dim]\n")
