import pytest
from pydantic import ValidationError

from main.core.scope import classify_target_scope
from main.schema.api_evidence import (
    ApiEvidence,
    ApiInventory,
    ApiParameter,
    ApiProvenance,
    load_api_inventory,
)
from main.schema.api_classification import classify_api_evidence


def test_canonical_api_evidence_preserves_auditable_reconstruction_without_values():
    evidence = ApiEvidence(
        url="https://api.example.com/public/v1/login",
        method="post",
        raw_expression='publicProxy + "/v1/login"',
        evidence_status="inferred",
        confidence="medium",
        scope_status="in_scope",
        source="javascript-static-analysis",
        provenance=[ApiProvenance(
            source="javascript-static-analysis",
            artifact="raw/javascript/main.js",
            source_url="https://example.com/assets/main.js",
            source_location="1:2048",
            raw_expression='publicProxy + "/v1/login"',
            chain=["md", "fetch"],
        )],
        request_body_fields=[
            ApiParameter(name="userNumber", location="body", required=True),
        ],
        request_header_names=["Content-Type", "Content-Type"],
        wrapper_chain=["md", "fetch", "fetch"],
    )

    assert evidence.method == "POST"
    assert evidence.request_header_names == ["Content-Type"]
    assert evidence.wrapper_chain == ["md", "fetch"]
    assert "value" not in evidence.model_dump(mode="json")["request_body_fields"][0]


def test_api_inventory_rejects_unknown_fields_and_loads_legacy_records():
    with pytest.raises(ValidationError):
        ApiInventory.model_validate({"schema_version": 1, "entries": [], "secret": "no"})

    inventory = load_api_inventory([{
        "method": "POST",
        "url": "https://example.com/api/login",
        "status_code": 401,
        "confidence": "high",
        "disposition": "confirmed",
        "source": "katana-browser",
        "surface_type": "API endpoint",
    }])

    assert inventory.schema_version == 1
    assert inventory.entries[0].evidence_status == "observed"
    assert inventory.entries[0].route_disposition == "confirmed"
    assert inventory.entries[0].scope_status == "unknown"


def test_scope_evidence_classification_is_fail_closed_and_explanatory():
    scope = {"allow": ["api.example.com"], "deny": ["blocked.example.com"]}

    assert classify_target_scope("https://api.example.com/v1", scope) == "in_scope"
    assert classify_target_scope("https://blocked.example.com/v1", scope) == "out_of_scope"
    assert classify_target_scope("https://other.example.com/v1", scope) == "unknown"


def test_api_classification_prioritizes_in_scope_authentication_operation():
    operation = ApiEvidence(
        method="POST",
        url="https://example.com/public/v1/PasswordLogin",
        evidence_status="observed",
        confidence="high",
        scope_status="in_scope",
        source="katana-browser-xhr",
        request_body_fields=[
            ApiParameter(name="userNumber", location="body"),
            ApiParameter(name="accountId", location="body"),
        ],
    )

    classified = classify_api_evidence(operation)

    assert classified.purpose == "Authentication"
    assert classified.review_priority == "high"
    assert "Authentication / session state-machine review" in classified.suggested_manual_review
    assert "IDOR / BOLA review" in classified.suggested_manual_review


def test_api_classification_keeps_unknown_scope_at_low_priority():
    operation = ApiEvidence(
        method="POST",
        url="https://third-party.test/oauth/callback",
        evidence_status="observed",
        confidence="high",
        scope_status="unknown",
        source="katana-browser-xhr",
        query_parameters=[ApiParameter(name="redirect_uri", location="query")],
    )

    classified = classify_api_evidence(operation)

    assert classified.purpose == "OAuth/OIDC"
    assert classified.review_priority == "low"
    assert "scope unknown; review only" in classified.priority_reasons
    assert "SSRF / open-redirect review" in classified.suggested_manual_review
