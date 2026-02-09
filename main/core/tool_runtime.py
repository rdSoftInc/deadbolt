# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file tool_runtime.py
# @brief Tool execution and parsing contract definition.
#
# This module defines the ToolRuntime dataclass, which describes how an
# individual scanning tool is executed, how its output is parsed, and how
# results are optionally post-processed. It acts as a declarative contract
# between tool runners and the normalization pipeline.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from main.schema.normalize import Finding


@dataclass(frozen=True)
class ToolRuntime:
    """
    Declarative runtime definition for a scanning tool.

    This dataclass captures the functions and metadata required to execute a
    tool, parse its output into normalized findings, and optionally apply
    post-processing steps before results are consumed by the pipeline.
    """

    # Function responsible for executing the tool
    runner: Callable[[Path, Path], None]

    # Function responsible for parsing raw tool output into findings
    parser: Callable[[Path], List[Finding]]

    # Expected output filename produced by the tool (e.g. "httpx.json")
    output_name: str

    # Optional post-processing hook applied after parsing
    postprocess: Callable[[List[Finding]], None] | None = None

    # Optional subdirectory where raw output is written
    raw_subdir: Optional[str] = None