
import threading
import time

from datetime import datetime, timezone
from typing import Dict, Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.box import SIMPLE

class ExecutionTable:
    def __init__(self):

        self._lock = threading.Lock()

        self.console = Console()
        self.started_at: Dict[str, datetime] = {}
        self.status: Dict[str, str] = {}
        self.findings: Dict[str, Optional[int]] = {}
        self._running = False
        self._ticker = None
        self.ended_at: Dict[str, datetime] = {}

        self.latest_versions: Dict[str, Optional[str]] = {}
        self.update_status: Dict[str, str] = {}

        self.versions = {}

        self.live = Live(self._render(), console=self.console, refresh_per_second=60)

    def start(self):
        self._running = True
        self.live.start()

        self._ticker = threading.Thread(
            target=self._tick,
            daemon=True,
        )
        self._ticker.start()

    def stop(self):
        self._running = False
        self.live.stop()

    def _refresh(self):
        with self._lock:
            self.live.update(self._render(), refresh=True)
    
    def _tick(self):
        while self._running:
            self._refresh()
            time.sleep(0.05)  # 50ms

    def register_tool(self, tool: str, version: str):
        self.versions[tool] = version
        self.status[tool] = "queued"
        self.findings[tool] = None
        self.latest_versions[tool] = None
        self.update_status[tool] = "checking"

    def tool_started(self, tool: str):
        self.started_at[tool] = datetime.now(timezone.utc)
        self.status[tool] = "running"
        self._refresh()

    def tool_finished(self, tool: str, findings: int):
        self.status[tool] = "done"
        self.findings[tool] = findings
        self.ended_at[tool] = datetime.now(timezone.utc)
        self._refresh()

    def tool_failed(self, tool: str):
        self.status[tool] = "failed"
        self.findings[tool] = 0
        self.ended_at[tool] = datetime.now(timezone.utc)
        self._refresh()

    def tool_skipped(self, tool: str):
        self.status[tool] = "skipped"
        self.findings[tool] = None
        self._refresh()

    def _render(self) -> Table:
        table = Table(
            box=SIMPLE,
            show_lines=False,
            expand=False,
            padding=(0, 3),
        )

        table.add_column("Tool", style="bold cyan", no_wrap=True)
        table.add_column("Version", style="dim")
        table.add_column("Update", justify="center", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Duration", justify="right", style="magenta")
        table.add_column("Findings", justify="right", style="bold")

        for tool in sorted(self.status.keys()):
            # duration
            duration = "-"
            if tool in self.started_at:
                end = self.ended_at.get(tool)
                delta = (end or datetime.now(timezone.utc)) - self.started_at[tool]
                duration = f"{delta.total_seconds():.1f}s"

            # status coloring
            raw_status = self.status[tool]

            if raw_status == "queued":
                status = "[dim]QUEUED[/dim]"
            elif raw_status == "running":
                status = "[yellow]RUNNING[/yellow]"
            elif raw_status == "done":
                status = "[green]DONE[/green]"
            elif raw_status == "skipped":
                status = "[dim]SKIPPED[/dim]"
            else:
                status = "[red]FAILED[/red]"

            findings = (
                str(self.findings[tool])
                if self.findings[tool] is not None
                else "—"
            )

            update = self.update_status.get(tool, "—")

            table.add_row(
                tool,
                self.versions.get(tool, "—"),
                update,
                status,
                duration,
                findings,
            )

        return table