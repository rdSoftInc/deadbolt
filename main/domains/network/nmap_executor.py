"""Hardened Docker execution for one precompiled Nmap phase."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
import re
import subprocess
import threading
import time
from typing import Callable

from main.domains.network.nmap_policy import NmapPhase, NmapPlan


class NetworkExecutionCancelled(RuntimeError):
    """Raised after an active Nmap container has been stopped cleanly."""


@dataclass(frozen=True)
class PhaseExecution:
    returncode: int
    duration_seconds: float
    log_path: Path
    timed_out: bool = False


_TIMEOUTS = {"safe": 1800, "standard": 7200, "deep": 28800}
_CID = re.compile(r"^[0-9a-f]{12,64}$")


def docker_command(plan: NmapPlan, phase: NmapPhase, run_dir: Path, cidfile: Path) -> list[str]:
    """Build a least-privilege Docker command without invoking a shell."""

    safe_run = re.sub(r"[^a-z0-9_.-]", "-", run_dir.name.lower())[-40:]
    safe_phase = re.sub(r"[^a-z0-9_.-]", "-", phase.name.lower())[-30:]
    command = [
        "docker", "run", "--rm", "--init",
        "--name", f"deadbolt-{safe_run}-{safe_phase}",
        "--cidfile", str(cidfile),
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
    ]
    if phase.requires_raw_socket:
        command.extend(("--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN"))
    command.extend(("--volume", f"{run_dir.resolve()}:/deadbolt:rw", plan.image, *phase.arguments))
    return command


def _stop_container(cidfile: Path, process: subprocess.Popen) -> None:
    cid = cidfile.read_text(encoding="utf-8").strip() if cidfile.is_file() else ""
    if _CID.fullmatch(cid):
        subprocess.run(
            ["docker", "stop", "--time", "5", cid],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    elif process.poll() is None:
        process.terminate()


def execute_nmap_phase(
    plan: NmapPlan,
    phase: NmapPhase,
    run_dir: Path,
    *,
    on_output: Callable[[str], None] | None = None,
    timeout_seconds: int | None = None,
) -> PhaseExecution:
    """Run one phase, stream its combined output to disk, and remain cancellable."""

    raw = run_dir / "raw"
    logs = run_dir / "logs"
    raw.mkdir(exist_ok=True)
    logs.mkdir(exist_ok=True)
    log_path = logs / f"nmap-{phase.name}.log"
    cidfile = run_dir / "work" / f".nmap-{phase.name}.cid"
    cidfile.unlink(missing_ok=True)
    command = docker_command(plan, phase, run_dir, cidfile)
    started = time.monotonic()
    limit = timeout_seconds or _TIMEOUTS[plan.mode.value]
    queue: Queue[str | None] = Queue()

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        log_path.write_text(f"Unable to start Docker: {exc}\n", encoding="utf-8")
        return PhaseExecution(127, time.monotonic() - started, log_path)

    def read_output() -> None:
        assert process.stdout is not None
        for line in iter(process.stdout.readline, ""):
            queue.put(line)
        queue.put(None)

    threading.Thread(target=read_output, daemon=True).start()
    timed_out = False
    try:
        with log_path.open("w", encoding="utf-8") as log:
            stream_done = False
            while process.poll() is None or not stream_done:
                try:
                    line = queue.get(timeout=0.2)
                    if line is None:
                        stream_done = True
                    else:
                        log.write(line)
                        log.flush()
                        if on_output:
                            on_output(line.rstrip())
                except Empty:
                    pass
                if process.poll() is None and time.monotonic() - started > limit:
                    timed_out = True
                    _stop_container(cidfile, process)
            returncode = process.wait(timeout=15)
    except KeyboardInterrupt as exc:
        _stop_container(cidfile, process)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
        raise NetworkExecutionCancelled("network assessment cancelled; active Nmap phase stopped") from exc
    finally:
        cidfile.unlink(missing_ok=True)
    if timed_out and returncode == 0:
        returncode = 124
    return PhaseExecution(returncode, time.monotonic() - started, log_path, timed_out)
