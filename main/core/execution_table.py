# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file execution_table.py
# @brief Live execution status table for Deadbolt scanning workflows.
#
# This module defines the ExecutionTable class, which renders a real-time,
# terminal-based status dashboard using Rich. It tracks tool execution state,
# durations, findings count, and update information while scans are running.
#
# The table is updated continuously from a background thread to provide a
# responsive, non-blocking view of scan progress across multiple tools.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import threading
import time
from datetime import datetime, timezone
from typing import Dict, Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.box import SIMPLE


class ExecutionTable:
    """
    Live-rendered execution status table.

    This class maintains state for multiple scanning tools and continuously
    renders their execution progress, duration, version, update status, and
    findings count to the terminal using Rich's Live display.
    """

    def __init__(self):
        """
        Initialize the execution table and its internal state.

        Sets up synchronization primitives, tracking structures, and the
        Rich Live renderer used to update the table in real time.
        """
        self._lock = threading.Lock()

        self.console = Console()

        # Per-tool execution timestamps
        self.started_at: Dict[str, datetime] = {}
        self.ended_at: Dict[str, datetime] = {}

        # Per-tool execution state and results
        self.status: Dict[str, str] = {}
        self.findings: Dict[str, Optional[int]] = {}

        # Version and update tracking
        self.versions: Dict[str, str] = {}
        self.latest_versions: Dict[str, Optional[str]] = {}
        self.update_status: Dict[str, str] = {}

        # Live rendering control
        self._running = False
        self._ticker = None

        # Rich Live display instance
        self.live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=60,
        )

    def start(self):
        """
        Start the live table rendering loop.

        This enables the Rich Live display and launches a background thread
        responsible for periodically refreshing the table contents.
        """
        self._running = True
        self.live.start()

        self._ticker = threading.Thread(
            target=self._tick,
            daemon=True,
        )
        self._ticker.start()

    def stop(self):
        """
        Stop the live table rendering loop.

        Performs a final refresh and cleanly stops the Rich Live display.
        """
        self._refresh()
        self._running = False
        self.live.stop()

    def _refresh(self):
        """
        Refresh the rendered table.

        This method is synchronized to prevent concurrent render updates
        from multiple threads.
        """
        with self._lock:
            self.live.update(self._render(), refresh=True)

    def _tick(self):
        """
        Periodic refresh loop for live rendering.

        Runs in a background thread and refreshes the table at a fixed
        interval to keep durations and statuses up to date.
        """
        while self._running:
            self._refresh()
            time.sleep(0.05)  # 50ms refresh interval

    def register_tool(self, tool: str, version: str):
        """
        Register a tool with the execution table.

        Initializes tracking state for a tool before execution begins.
        """
        self.versions[tool] = version
        self.status[tool] = "queued"
        self.findings[tool] = None
        self.latest_versions[tool] = None
        self.update_status[tool] = "checking"

    def tool_started(self, tool: str):
        """
        Mark a tool as started.

        Records the start time and updates the execution status.
        """
        self.started_at[tool] = datetime.now(timezone.utc)
        self.status[tool] = "running"
        self._refresh()

    def tool_finished(self, tool: str, findings: int):
        """
        Mark a tool as successfully completed.

        Records the end time, final findings count, and updates status.
        """
        self.status[tool] = "done"
        self.findings[tool] = findings
        self.ended_at[tool] = datetime.now(timezone.utc)
        self._refresh()

    def tool_failed(self, tool: str):
        """
        Mark a tool execution as failed.

        Records the failure state and end time.
        """
        self.status[tool] = "failed"
        self.findings[tool] = 0
        self.ended_at[tool] = datetime.now(timezone.utc)
        self._refresh()

    def tool_skipped(self, tool: str):
        """
        Mark a tool as skipped.

        Used when a tool is intentionally not executed.
        """
        self.status[tool] = "skipped"
        self.findings[tool] = None
        self._refresh()

    def _render(self) -> Table:
        """
        Render the execution status table.

        Constructs and returns a Rich Table reflecting the current state
        of all registered tools.
        """
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
            # Compute execution duration
            duration = "-"
            if tool in self.started_at:
                end = self.ended_at.get(tool)
                delta = (end or datetime.now(timezone.utc)) - self.started_at[tool]
                duration = f"{delta.total_seconds():.1f}s"

            # Status formatting and coloring
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

            update = self.update_status.get(tool) or "—"

            table.add_row(
                tool,
                self.versions.get(tool, "—"),
                update,
                status,
                duration,
                findings,
            )

        return table