"""Report-safe response and technology intelligence helpers."""

from __future__ import annotations

from collections.abc import Iterable

from main.schema.api_evidence import ApiEvidence


_INFRASTRUCTURE_MARKERS = {
    "akamai", "apache", "aws", "azure front door", "cloudflare", "cloudfront",
    "citrix", "envoy", "fastly", "haproxy", "imperva", "nginx", "varnish",
}
_INFRASTRUCTURE_COOKIE_MARKERS = (
    "citrix_ns", "ns_af", "awsalb", "awsalbcors", "cf_", "akamai", "incap_",
)


def infrastructure_cookie_names(names: Iterable[str]) -> list[str]:
    """Return cookie names attributable to common delivery infrastructure."""

    return list(dict.fromkeys(
        str(name) for name in names
        if any(marker in str(name).lower() for marker in _INFRASTRUCTURE_COOKIE_MARKERS)
    ))


def classify_technologies(
    technologies: Iterable[str],
    *,
    webserver: str | None = None,
    cdn_name: str | None = None,
) -> tuple[list[str], list[str]]:
    """Separate application technologies from delivery/infrastructure layers."""

    application: list[str] = []
    infrastructure: list[str] = []
    candidates = [*technologies, webserver, cdn_name]
    for candidate in candidates:
        if not candidate:
            continue
        value = str(candidate).strip()
        if not value:
            continue
        destination = (
            infrastructure
            if any(marker in value.lower() for marker in _INFRASTRUCTURE_MARKERS)
            else application
        )
        if value not in destination:
            destination.append(value)
    return application, infrastructure


def enrich_response_intelligence(
    evidence: ApiEvidence,
    *,
    technologies: Iterable[str] = (),
    webserver: str | None = None,
    cdn_name: str | None = None,
) -> ApiEvidence:
    """Attach bounded, non-vulnerability response intelligence to an operation."""

    application, infrastructure = classify_technologies(
        technologies, webserver=webserver, cdn_name=cdn_name,
    )
    evidence.application_technologies = list(dict.fromkeys(
        [*evidence.application_technologies, *application]
    ))
    evidence.infrastructure_technologies = list(dict.fromkeys(
        [*evidence.infrastructure_technologies, *infrastructure]
    ))
    content_type = (evidence.response_content_type or "").lower()
    if "application/problem+json" in content_type:
        signal = (
            "RFC Problem Details response; commonly used by ASP.NET and other frameworks "
            "(heuristic, not framework proof)"
        )
        if signal not in evidence.framework_signals:
            evidence.framework_signals.append(signal)
    return evidence
