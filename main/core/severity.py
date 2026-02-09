# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file severity.py
# @brief Severity normalization and comparison utilities.
#
# This module defines a canonical severity ordering and helper functions
# for comparing issue severities in a consistent and predictable way across
# Deadbolt analysis and reporting workflows.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

# Canonical severity ranking used across Deadbolt
SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_at_least(severity: str, minimum: str) -> bool:
    """
    Compare two severity levels.

    Returns True if the provided severity is greater than or equal to the
    specified minimum severity based on the canonical severity ordering.
    """
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)