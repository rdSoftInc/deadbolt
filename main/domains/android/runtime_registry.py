# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runtime_registry.py
# @brief Android tool runtime registry.
#
# This module defines the runtime configuration for Android analysis tools.
# Each entry declares how a tool is executed, how its output is parsed, and
# what output artifact is expected. The registry is consumed by the Android
# runner to orchestrate tool execution and normalization.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from main.core.tool_runtime import ToolRuntime

# ──────────────── Static Analysis ────────────────

from main.tools.apktool.runner import run_apktool
from main.tools.apktool.parser import parse_apktool

from main.tools.jadx.runner import run_jadx
from main.tools.jadx.parser import parse_jadx

from main.tools.androguard.runner import run_androguard
from main.tools.androguard.parser import parse_androguard

# ──────────────── Analysis ────────────────

from main.tools.mobsf.runner import run_mobsf
from main.tools.mobsf.parser import parse_mobsf


# ──────────────── Runtime Registry ────────────────

# Declarative mapping of tool names to their execution runtime definitions
TOOL_RUNTIMES = {

    # ---------------- Static ----------------

    "apktool": ToolRuntime(
        runner=run_apktool,
        parser=parse_apktool,
        output_name="apktool.json",
    ),

    "jadx": ToolRuntime(
        runner=run_jadx,
        parser=parse_jadx,
        output_name="jadx.json",
    ),

    "androguard": ToolRuntime(
        runner=run_androguard,
        parser=parse_androguard,
        output_name="androguard.json",
    ),

    # ---------------- Analysis ----------------

    "mobsf": ToolRuntime(
        runner=run_mobsf,
        parser=parse_mobsf,
        output_name="mobsf.json",
    ),
}