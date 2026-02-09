# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file scope.py
# @brief Target scope loading and validation utilities.
#
# This module provides helper functions for loading a scope definition and
# validating scan targets against it. Scope enforcement ensures that Deadbolt
# only operates on explicitly permitted hosts and prevents accidental or
# unauthorized scanning outside defined boundaries.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pathlib import Path
from urllib.parse import urlparse
import yaml


class ScopeError(Exception):
    """
    Raised when one or more scan targets violate the defined scope.
    """
    pass


def load_scope(scope_file: Path) -> dict:
    """
    Load a scope definition from a YAML file.

    The scope file may define allow and deny lists used to control which
    targets are permitted during scanning.
    """
    with scope_file.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def validate_targets(targets_file: Path, scope_file: Path):
    """
    Validate scan targets against a defined scope.

    Each target is parsed and checked against allow and deny lists defined
    in the scope file. Any violations are collected and raised as a single
    ScopeError to provide clear feedback to the user.
    """
    scope = load_scope(scope_file)
    allowed = set(scope.get("allow", []))
    denied = set(scope.get("deny", []))

    violations = []

    with targets_file.open() as f:
        for line in f:
            target = line.strip()
            if not target:
                continue

            host = urlparse(target).hostname
            if not host:
                continue

            if host in denied:
                violations.append(f"{host} is explicitly denied")

            if allowed and host not in allowed:
                violations.append(f"{host} is not in allow list")

    if violations:
        raise ScopeError("Scope violation:\n" + "\n".join(violations))