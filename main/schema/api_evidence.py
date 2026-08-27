"""Canonical, report-safe evidence model for discovered web APIs."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


API_INVENTORY_SCHEMA_VERSION = 1

EvidenceStatus = Literal["observed", "inferred", "discovered"]
Confidence = Literal["high", "medium", "low"]
ScopeStatus = Literal["in_scope", "out_of_scope", "unknown"]
ParameterLocation = Literal["query", "path", "body", "header"]


class ApiParameter(BaseModel):
    """A parameter definition without captured secret or user-supplied values."""

    model_config = ConfigDict(extra="forbid")

    name: str
    location: ParameterLocation
    data_type: str | None = None
    required: bool | None = None
    source: str | None = None


class ApiProvenance(BaseModel):
    """One auditable step that contributed to an API reconstruction."""

    model_config = ConfigDict(extra="forbid")

    source: str
    artifact: str | None = None
    source_url: str | None = None
    source_location: str | None = None
    raw_expression: str | None = None
    chain: list[str] = Field(default_factory=list)


class RequestSchemaConflict(BaseModel):
    """Contradictory request-schema evidence retained for analyst review."""

    model_config = ConfigDict(extra="forbid")

    field_name: str
    location: ParameterLocation
    attribute: Literal["data_type", "required"]
    observed: str
    inferred: str


class ApiEvidence(BaseModel):
    """One understood, inferred, or string-discovered API operation."""

    model_config = ConfigDict(extra="forbid")

    url: str
    method: str | None = None
    raw_url: str | None = None
    raw_expression: str | None = None
    evidence_status: EvidenceStatus
    confidence: Confidence
    scope_status: ScopeStatus = "unknown"
    source: str
    provenance: list[ApiProvenance] = Field(default_factory=list)
    query_parameters: list[ApiParameter] = Field(default_factory=list)
    path_parameters: list[ApiParameter] = Field(default_factory=list)
    request_body_fields: list[ApiParameter] = Field(default_factory=list)
    request_schema_conflicts: list[RequestSchemaConflict] = Field(default_factory=list)
    request_header_names: list[str] = Field(default_factory=list)
    response_fields: list[str] = Field(default_factory=list)
    response_header_names: list[str] = Field(default_factory=list)
    api_version_indicators: list[str] = Field(default_factory=list)
    application_technologies: list[str] = Field(default_factory=list)
    infrastructure_technologies: list[str] = Field(default_factory=list)
    framework_signals: list[str] = Field(default_factory=list)
    infrastructure_cookie_names: list[str] = Field(default_factory=list)
    client_validation_rules: list[str] = Field(default_factory=list)
    status_code: int | None = None
    request_content_type: str | None = None
    response_content_type: str | None = None
    credentials_mode: str | None = None
    auth_context: Literal["authenticated", "unauthenticated", "unknown"] = "unknown"
    wrapper_chain: list[str] = Field(default_factory=list)
    preflight_observed: bool = False
    purpose: str | None = None
    review_priority: Literal["high", "medium", "low"] = "low"
    priority_score: int = 0
    priority_reasons: list[str] = Field(default_factory=list)
    suggested_manual_review: list[str] = Field(default_factory=list)
    route_disposition: str | None = None
    route_confidence: str | None = None
    surface_type: str = "API endpoint"

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str | None) -> str | None:
        return value.upper() if value else None

    @field_validator(
        "request_header_names", "response_header_names", "response_fields",
        "api_version_indicators", "application_technologies",
        "infrastructure_technologies", "framework_signals",
        "infrastructure_cookie_names", "client_validation_rules",
        "wrapper_chain", "priority_reasons", "suggested_manual_review",
    )
    @classmethod
    def unique_strings(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(item for item in value if item))


class ApiInventory(BaseModel):
    """Versioned envelope used for durable API evidence artifacts."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = API_INVENTORY_SCHEMA_VERSION
    entries: list[ApiEvidence] = Field(default_factory=list)


def load_api_inventory(payload: object) -> ApiInventory:
    """Read the canonical envelope and upgrade the former list format."""

    if isinstance(payload, dict) and "entries" in payload:
        return ApiInventory.model_validate(payload)
    if not isinstance(payload, list):
        return ApiInventory()

    entries = []
    for item in payload:
        if not isinstance(item, dict) or not item.get("url"):
            continue
        source = str(item.get("source") or "legacy")
        entries.append(ApiEvidence(
            url=str(item["url"]),
            method=item.get("method"),
            evidence_status="observed" if source == "katana-browser" else "discovered",
            confidence=str(item.get("confidence") or "low")
            if str(item.get("confidence") or "low") in {"high", "medium", "low"}
            else "low",
            source=source,
            status_code=item.get("status_code"),
            route_disposition=item.get("disposition"),
            route_confidence=item.get("confidence"),
            surface_type=str(item.get("surface_type") or "API endpoint"),
            provenance=[ApiProvenance(source=source)],
        ))
    return ApiInventory(entries=entries)
