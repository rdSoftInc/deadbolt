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


def target_host(target: str) -> str | None:
    """Extract a normalized host from a URL, bare host, or host/path value."""

    value = target.strip().split(" :: ", 1)[0]
    if not value or value.startswith("/"):
        return None
    parsed = urlparse(value if "://" in value else f"//{value}")
    return parsed.hostname.lower().rstrip(".") if parsed.hostname else None


def host_in_scope(host: str, scope: dict) -> bool:
    """Apply fail-closed exact or explicit wildcard rules to one hostname."""

    allowed = {str(item).lower().rstrip(".") for item in scope.get("allow", [])}
    denied = {str(item).lower().rstrip(".") for item in scope.get("deny", [])}
    normalized = host.lower().rstrip(".")

    return bool(allowed) and not any(
        _host_matches_pattern(normalized, pattern) for pattern in denied
    ) and any(_host_matches_pattern(normalized, pattern) for pattern in allowed)


def classify_target_scope(target: str, scope: dict) -> str:
    """Classify evidence without treating an unlisted host as authorized.

    ``unknown`` is intentionally distinct from an explicit deny. Both remain
    ineligible for active scanning; the distinction is for analyst review.
    """

    host = target_host(target)
    if not host:
        return "unknown"
    normalized = host.lower().rstrip(".")
    denied = {str(item).lower().rstrip(".") for item in scope.get("deny", [])}
    allowed = {str(item).lower().rstrip(".") for item in scope.get("allow", [])}
    if any(_host_matches_pattern(normalized, pattern) for pattern in denied):
        return "out_of_scope"
    if any(_host_matches_pattern(normalized, pattern) for pattern in allowed):
        return "in_scope"
    return "unknown"


def _host_matches_pattern(host: str, pattern: str) -> bool:
    """Match normalized hosts using Deadbolt's explicit wildcard semantics."""

    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != pattern[2:]
    return host == pattern


def filter_in_scope(items: list[str], scope: dict) -> tuple[list[str], list[str]]:
    """Partition absolute targets into permitted and rejected values."""

    accepted = []
    rejected = []
    for item in items:
        host = target_host(item)
        if host and host_in_scope(host, scope):
            accepted.append(item)
        else:
            rejected.append(item)
    return accepted, rejected


def validate_targets(targets_file: Path, scope_file: Path):
    """
    Validate scan targets against a defined scope.

    Each target is parsed and checked against allow and deny lists defined
    in the scope file. Any violations are collected and raised as a single
    ScopeError to provide clear feedback to the user.
    """
    scope = load_scope(scope_file)
    violations = []
    allowed = {str(item).lower().rstrip(".") for item in scope.get("allow", [])}
    denied = {str(item).lower().rstrip(".") for item in scope.get("deny", [])}
    if not allowed:
        raise ScopeError(
            "Scope violation:\nscope allow list is empty; explicit authorization is required"
        )

    with targets_file.open() as f:
        for line in f:
            target = line.strip()
            if not target:
                continue

            host = target_host(target)
            if not host:
                violations.append(f"cannot determine host for {target!r}")
                continue

            if any(_host_matches_pattern(host, pattern) for pattern in denied):
                violations.append(f"{host} is explicitly denied")
            elif not any(_host_matches_pattern(host, pattern) for pattern in allowed):
                violations.append(f"{host} is not in allow list")

    if violations:
        raise ScopeError("Scope violation:\n" + "\n".join(violations))
