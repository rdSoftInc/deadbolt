# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runtime_registry.py
# @brief iOS tool runtime registry.
#
# This module defines the runtime configuration for iOS analysis tools.
# Each entry specifies how a tool is executed, how its output is parsed,
# and which output artifact is expected. The registry is consumed by the
# iOS runner to orchestrate tool execution and normalization.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from main.core.tool_runtime import ToolRuntime

# ──────────────── Static Analysis ────────────────

from main.tools.mobsf.runner import run_mobsf
from main.tools.mobsf.parser import parse_mobsf


# ──────────────── Runtime Registry ────────────────

# Declarative mapping of tool names to their execution runtime definitions
TOOL_RUNTIMES = {

    "mobsf": ToolRuntime(
        runner=run_mobsf,
        parser=parse_mobsf,
        output_name="mobsf.json",
    ),

}