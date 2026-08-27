"""Named, whole-pipeline web assessment profiles."""

from dataclasses import dataclass
from enum import Enum


class WebScanProfile(str, Enum):
    SAFE = "safe"
    STANDARD = "standard"
    DEEP = "deep"
    # Accepted only for compatibility with commands and runs created before
    # the operational modes were named Safe/Standard/Deep.
    QUICK = "quick"
    DEEP_SPA = "deep-spa"


PROFILE_LABELS = {
    WebScanProfile.SAFE: "Safe",
    WebScanProfile.STANDARD: "Standard",
    WebScanProfile.DEEP: "Deep",
    WebScanProfile.QUICK: "Safe (legacy quick)",
    WebScanProfile.DEEP_SPA: "Deep (legacy deep-spa)",
}


@dataclass(frozen=True)
class WebScanPolicy:
    httpx_threads: int
    httpx_rate: int
    httpx_timeout: int
    ffuf_threads: int
    ffuf_timeout: int
    nuclei_concurrency: int
    nuclei_rate: int
    nuclei_timeout: int
    nuclei_retries: int


PROFILE_POLICIES = {
    WebScanProfile.SAFE: WebScanPolicy(1, 1, 10, 1, 15, 1, 1, 10, 0),
    WebScanProfile.STANDARD: WebScanPolicy(50, 150, 10, 20, 10, 50, 150, 5, 0),
    WebScanProfile.DEEP: WebScanPolicy(75, 200, 15, 30, 15, 50, 100, 10, 1),
}


def normalize_web_profile(value: WebScanProfile | str) -> WebScanProfile:
    """Normalize API callers while rejecting unknown profile names early."""

    profile = value if isinstance(value, WebScanProfile) else WebScanProfile(value)
    if profile is WebScanProfile.QUICK:
        return WebScanProfile.SAFE
    if profile is WebScanProfile.DEEP_SPA:
        return WebScanProfile.DEEP
    return profile


def policy_for(value: WebScanProfile | str) -> WebScanPolicy:
    return PROFILE_POLICIES[normalize_web_profile(value)]


def capped_rate(configured: int, maximum: float | None) -> int:
    """Apply an engagement ceiling to an integer requests-per-second setting."""

    if maximum is None:
        return configured
    return max(1, min(configured, int(maximum)))
