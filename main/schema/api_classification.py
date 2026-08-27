"""Explainable endpoint-purpose and manual-review classification."""

from __future__ import annotations

from urllib.parse import urlsplit

from main.schema.api_evidence import ApiEvidence


PURPOSE_MARKERS = [
    ("OAuth/OIDC", {"oauth", "oidc", "authorize", "callback", "token"}),
    ("Authentication", {"login", "logon", "signin", "sign-in", "otp", "digipass", "password", "session"}),
    ("File handling", {"upload", "download", "file", "document", "attachment", "export", "import"}),
    ("Redirect", {"redirect", "returnurl", "return-url", "continue", "next"}),
    ("Object access", {"account", "customer", "profile", "user", "order", "invoice", "payment"}),
    ("Health/status", {"status", "health", "ready", "readiness", "metrics"}),
    ("Configuration", {"config", "configuration", "manifest", "resources", "settings"}),
    ("GraphQL", {"graphql", "gql"}),
]

PARAMETER_REVIEW = [
    ({"url", "uri", "callback", "redirect", "redirecturi", "redirect_uri", "returnurl", "next"}, "SSRF / open-redirect review"),
    ({"file", "filename", "filepath", "path", "document", "download", "resource", "template"}, "Path-traversal / file-handling review"),
    ({"id", "uuid", "account", "accountid", "account_id", "customer", "customerid", "customer_id", "userid", "user_id"}, "IDOR / BOLA review"),
]


def _tokens(entry: ApiEvidence) -> set[str]:
    path = urlsplit(entry.url).path.lower()
    normalized = path.replace("-", "/").replace("_", "/").replace(".", "/")
    return {token for token in normalized.split("/") if token}


def classify_api_evidence(entry: ApiEvidence) -> ApiEvidence:
    """Enrich one operation without asserting that a vulnerability exists."""

    tokens = _tokens(entry)
    purpose = "Application API"
    for candidate, markers in PURPOSE_MARKERS:
        if any(marker in token for token in tokens for marker in markers):
            purpose = candidate
            break
    if entry.surface_type == "static resource":
        purpose = "Static"

    parameter_names = {
        parameter.name.lower()
        for parameter in [
            *entry.query_parameters,
            *entry.path_parameters,
            *entry.request_body_fields,
        ]
    }
    reviews: list[str] = []
    for markers, review in PARAMETER_REVIEW:
        if parameter_names & markers:
            reviews.append(review)
    if purpose in {"Authentication", "OAuth/OIDC"}:
        reviews.append("Authentication / session state-machine review")
    if purpose == "Object access":
        reviews.append("Authorization and cross-account object-access review")
    if entry.method in {"POST", "PUT", "PATCH", "DELETE"}:
        reviews.append("Authorization and business-logic review")

    score = 0
    reasons: list[str] = []
    if entry.scope_status == "in_scope":
        score += 25
        reasons.append("explicitly in scope")
    elif entry.scope_status == "unknown":
        score -= 20
        reasons.append("scope unknown; review only")
    else:
        score -= 100
        reasons.append("out of scope; evidence only")
    evidence_points = {"observed": 20, "inferred": 10, "discovered": 0}[entry.evidence_status]
    score += evidence_points
    if evidence_points:
        reasons.append(f"{entry.evidence_status} operation")
    if purpose in {"Authentication", "OAuth/OIDC", "File handling", "Redirect", "Object access"}:
        score += 20
        reasons.append(f"security-relevant purpose: {purpose.lower()}")
    elif purpose in {"Health/status", "Configuration", "Static"}:
        score -= 10
        reasons.append(f"lower-priority purpose: {purpose.lower()}")
    if reviews:
        score += 15
        reasons.append("security-relevant method or parameter names")
    if entry.method in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 5
        reasons.append(f"state-changing method: {entry.method}")

    if entry.scope_status != "in_scope":
        priority = "low"
    elif score >= 60:
        priority = "high"
    elif score >= 35:
        priority = "medium"
    else:
        priority = "low"

    return entry.model_copy(update={
        "purpose": purpose,
        "suggested_manual_review": list(dict.fromkeys(reviews)),
        "review_priority": priority,
        "priority_score": score,
        "priority_reasons": reasons,
    })
