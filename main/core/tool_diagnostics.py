"""Read-only lifecycle and environment diagnostics for Deadbolt tools."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
from typing import Callable

from main.core.scope import load_scope
from main.core.engagement import EngagementError, load_engagement
from main.core.tool_manifest import ToolConfig, load_tool_manifest
from main.execution.latest_version import get_latest_version
from main.execution.version import get_tool_version
from main.core.provider_config import provider_statuses


PACKAGE_ROOT = Path(__file__).parents[1]


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class ToolStatus:
    name: str
    domains: list[str]
    image: str
    expected: str
    installed: str | None
    upstream: str | None
    image_present: bool | None
    managed: bool
    status: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


CommandRunner = Callable[[list[str], float], CommandResult]


def run_command(command: list[str], timeout: float = 10) -> CommandResult:
    """Run a diagnostic command without mutating external state."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(result.returncode, result.stdout, result.stderr)
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandResult(127, stderr=str(exc))


def run_streaming_command(command: list[str], timeout: float = 10) -> CommandResult:
    """Run a command while mirroring combined output to the terminal."""

    if command[:2] == ["docker", "build"] and "--progress=plain" not in command:
        command = [*command[:2], "--progress=plain", *command[2:]]
    try:
        print(f"$ {shlex.join(command)}", flush=True)
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        lines = []
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="", flush=True)
            lines.append(line)
        returncode = process.wait(timeout=timeout)
        return CommandResult(returncode, stdout="".join(lines))
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandResult(127, stderr=str(exc))


def docker_cli_available() -> bool:
    return shutil.which("docker") is not None


def docker_daemon_available(command_runner: CommandRunner = run_command) -> tuple[bool, str]:
    if not docker_cli_available():
        return False, "Docker CLI not found in PATH"

    result = command_runner(["docker", "info", "--format", "{{.ServerVersion}}"], 10)
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        return False, message or "Docker daemon is unavailable"
    return True, result.stdout.strip() or "running"


def docker_image_exists(
    image: str,
    command_runner: CommandRunner = run_command,
) -> bool:
    result = command_runner(["docker", "image", "inspect", image], 10)
    return result.returncode == 0


def classify_tool_status(
    *,
    config: ToolConfig,
    image_present: bool,
    installed: str | None,
    upstream: str | None,
) -> tuple[str, str]:
    expected = config.display_version

    if not image_present:
        action = "build" if config.managed else "pull"
        return "missing", f"image missing; {action} {config.image}"
    if not installed or installed == "unknown":
        return "unverifiable", "image exists but installed version could not be detected"
    if installed.lstrip("v") != expected:
        return "rebuild_required", f"installed {installed}, expected {expected}"
    if upstream and upstream.lstrip("v") != expected:
        return "update_available", f"upstream {upstream}, pinned {expected}"
    if upstream is None:
        return "current_offline", "local image matches the manifest; upstream not checked"
    return "current", "installed, pinned, and upstream versions match"


def inspect_tool(
    config: ToolConfig,
    *,
    offline: bool = False,
    command_runner: CommandRunner = run_command,
    installed_resolver: Callable[[str], str] = get_tool_version,
    upstream_resolver: Callable[[str], str | None] = get_latest_version,
) -> ToolStatus:
    present = docker_image_exists(config.image, command_runner)
    installed = installed_resolver(config.image) if present else None
    upstream = None if offline else upstream_resolver(config.image)
    status, detail = classify_tool_status(
        config=config,
        image_present=present,
        installed=installed,
        upstream=upstream,
    )
    return ToolStatus(
        name=config.name,
        domains=list(config.domains),
        image=config.image,
        expected=config.display_version,
        installed=installed,
        upstream=upstream,
        image_present=present,
        managed=config.managed,
        status=status,
        detail=detail,
    )


def collect_tool_statuses(
    *,
    offline: bool = False,
    workers: int = 4,
    command_runner: CommandRunner = run_command,
    installed_resolver: Callable[[str], str] = get_tool_version,
    upstream_resolver: Callable[[str], str | None] = get_latest_version,
) -> list[ToolStatus]:
    """Inspect all configured tools concurrently while preserving manifest order."""

    configs = list(load_tool_manifest().tools.values())
    daemon_ok, daemon_detail = docker_daemon_available(command_runner)

    if not daemon_ok:
        def without_docker(config: ToolConfig) -> ToolStatus:
            upstream = None if offline else upstream_resolver(config.image)
            return ToolStatus(
                name=config.name,
                domains=list(config.domains),
                image=config.image,
                expected=config.display_version,
                installed=None,
                upstream=upstream,
                image_present=None,
                managed=config.managed,
                status="docker_unavailable",
                detail=daemon_detail,
            )

        with ThreadPoolExecutor(max_workers=max(1, min(workers, 8))) as executor:
            return list(executor.map(without_docker, configs))

    def inspect(config: ToolConfig) -> ToolStatus:
        return inspect_tool(
            config,
            offline=offline,
            command_runner=command_runner,
            installed_resolver=installed_resolver,
            upstream_resolver=upstream_resolver,
        )

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 8))) as executor:
        return list(executor.map(inspect, configs))


def _check_file(name: str, path: Path) -> DoctorCheck:
    if path.is_file():
        return DoctorCheck(name, "pass", str(path))
    return DoctorCheck(name, "fail", f"missing file: {path}")


def _check_directory(name: str, path: Path) -> DoctorCheck:
    if path.is_dir():
        return DoctorCheck(name, "pass", str(path))
    return DoctorCheck(name, "fail", f"missing directory: {path}")


def _check_engagements(workspace_root: Path) -> DoctorCheck:
    """Validate saved authorization contexts without exposing their contents."""

    engagement_root = workspace_root / "engagements"
    files = sorted(
        path
        for pattern in ("*.yaml", "*.yml")
        for path in engagement_root.glob(pattern)
        if path.name != "example.yaml"
    ) if engagement_root.is_dir() else []
    if not files:
        return DoctorCheck(
            "saved_engagements",
            "warn",
            "none saved; create and validate one before a bug-bounty, client, or network assessment",
        )

    invalid: list[str] = []
    insecure: list[str] = []
    for path in files:
        try:
            load_engagement(path)
        except (EngagementError, OSError):
            invalid.append(path.name)
            continue
        permissions = path.stat().st_mode & 0o777
        if permissions != 0o600:
            insecure.append(f"{path.name}={permissions:03o}")

    if invalid:
        return DoctorCheck(
            "saved_engagements",
            "fail",
            "invalid file(s): " + ", ".join(invalid),
        )
    if insecure:
        return DoctorCheck(
            "saved_engagements",
            "warn",
            "expected owner-only permissions 600: " + ", ".join(insecure),
        )
    return DoctorCheck(
        "saved_engagements",
        "pass",
        f"{len(files)} valid file(s); owner-only permissions verified",
    )


def _port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def run_doctor(
    *,
    command_runner: CommandRunner = run_command,
) -> list[DoctorCheck]:
    """Run non-destructive readiness checks for a Deadbolt installation."""

    checks: list[DoctorCheck] = []

    try:
        manifest = load_tool_manifest()
        checks.append(
            DoctorCheck("tool_manifest", "pass", f"schema 1; {len(manifest.tools)} tools")
        )
    except Exception as exc:
        checks.append(DoctorCheck("tool_manifest", "fail", str(exc)))
        return checks

    daemon_ok, daemon_detail = docker_daemon_available(command_runner)
    checks.append(
        DoctorCheck("docker_daemon", "pass" if daemon_ok else "fail", daemon_detail)
    )

    if daemon_ok:
        missing = [
            config.image
            for config in manifest.tools.values()
            if not docker_image_exists(config.image, command_runner)
        ]
        checks.append(
            DoctorCheck(
                "required_images",
                "pass" if not missing else "fail",
                "all configured images are present"
                if not missing
                else "missing: " + ", ".join(missing),
            )
        )
    else:
        checks.append(
            DoctorCheck("required_images", "skip", "Docker daemon unavailable")
        )

    workspace_root = Path.cwd()
    scope_path = workspace_root / "scope.yaml"
    try:
        scope = load_scope(scope_path)
        if not isinstance(scope, dict):
            raise ValueError("scope root must be a mapping")
        for key in ("allow", "deny"):
            if key in scope and not isinstance(scope[key], list):
                raise ValueError(f"scope.{key} must be a list")
        if not scope.get("allow"):
            raise ValueError(
                "scope.allow must contain at least one explicitly authorized host"
            )
        checks.append(
            DoctorCheck(
                "scope_config",
                "pass",
                f"{len(scope.get('allow', []))} allowed; {len(scope.get('deny', []))} denied",
            )
        )
    except Exception as exc:
        checks.append(DoctorCheck("scope_config", "fail", str(exc)))

    checks.extend(
        [
            _check_engagements(workspace_root),
            _check_file("wordlist_shallow", workspace_root / "wordlists" / "shallow.txt"),
            _check_file("wordlist_common", workspace_root / "wordlists" / "common.txt"),
            _check_file(
                "report_template_technical",
                PACKAGE_ROOT / "report" / "templates" / "technical.html.j2",
            ),
            _check_file(
                "report_template_stakeholder",
                PACKAGE_ROOT / "report" / "templates" / "stakeholder.html.j2",
            ),
            _check_directory("targets", workspace_root / "targets"),
        ]
    )

    providers = provider_statuses(workspace_root / ".env")
    configured = [item.name for item in providers if item.configured]
    checks.append(
        DoctorCheck(
            "optional_providers",
            "pass" if configured else "warn",
            ("configured: " + ", ".join(configured))
            if configured
            else "none configured; copy .env.example to .env when needed",
        )
    )

    port_ok = _port_available(8000)
    checks.append(
        DoctorCheck(
            "mobsf_port_8000",
            "pass" if port_ok else "warn",
            "available" if port_ok else "already in use; MobSF may already be running",
        )
    )
    return checks
