# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file normalize.py
# @brief Normalized finding schema for Deadbolt.
#
# This module defines the canonical Finding model used across all Deadbolt
# domains (web, Android, iOS). All tool outputs are parsed and normalized into
# this schema to enable consistent aggregation, reporting, and post-processing.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Any, Dict, List, Optional


class Finding(BaseModel):
    """
    Canonical normalized finding representation.

    This model represents both attack surface artifacts (e.g. assets, paths)
    and vulnerability findings in a unified structure. Domain- and tool-
    specific data is captured via optional fields and the metadata map.
    """

    # -------------------------------
    # Core identity
    # -------------------------------

    asset: str
    title: str
    tool: str

    # Classification of the finding:
    # - asset    : discovered host / service / endpoint
    # - path     : discovered URL or route
    # - finding  : vulnerability or security issue
    kind: str  # asset | path | finding

    # -------------------------------
    # Web-oriented attributes
    # -------------------------------

    status_code: Optional[int] = None
    technologies: List[str] = Field(default_factory=list)
    webserver: Optional[str] = None
    cdn: Optional[bool] = None
    cdn_name: Optional[str] = None

    # -------------------------------
    # Vulnerability attributes
    # -------------------------------

    severity: Optional[str] = None
    template_id: Optional[str] = None

    # -------------------------------
    # Generic attributes
    # -------------------------------

    # Number of times this finding was observed
    occurrences: int = 1

    # Timestamp when the finding was generated or observed
    timestamp: datetime

    # Path to evidence artifact (file, request/response dump, etc.)
    evidence_path: str

    # -------------------------------
    # Domain- or tool-specific enrichment
    # -------------------------------

    # Arbitrary structured metadata supplied by parsers
    metadata: Dict[str, Any] = Field(default_factory=dict)