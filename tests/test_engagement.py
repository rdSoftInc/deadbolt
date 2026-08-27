import pytest

from main.core.engagement import (
    Engagement,
    EngagementError,
    engagement_path,
    engagement_slug,
    load_engagement,
    save_engagement,
)


def _engagement(**overrides) -> Engagement:
    payload = {
        "name": "Acme External 2026",
        "engagement_type": "client",
        "mode": "safe",
        "scope": {
            "allow_hosts": ["example.com", "*.example.com"],
            "deny_hosts": ["admin.example.com"],
            "allow_networks": ["10.20.30.4/24"],
            "allow_ports": [443, 80, 443],
            "exclude_paths": ["/payment/*"],
        },
        "traffic": {
            "automation_allowed": True,
            "max_requests_per_second": 1,
            "user_agent": "Deadbolt authorized assessment",
            "headers": {"X-Bug-Bounty": "researcher-name"},
        },
    }
    payload.update(overrides)
    return Engagement.model_validate(payload)


def test_engagement_round_trip_is_strict_and_owner_only(tmp_path):
    original = _engagement()
    destination = save_engagement(original, tmp_path / "acme.yaml")

    assert load_engagement(destination) == original
    assert destination.stat().st_mode & 0o777 == 0o600
    assert original.scope.allow_networks == ["10.20.30.0/24"]
    assert original.scope.allow_ports == [80, 443]
    assert original.web_scope() == {
        "allow": ["example.com", "*.example.com"],
        "deny": ["admin.example.com"],
    }


def test_engagement_persists_deduplicated_default_targets(tmp_path):
    original = _engagement(
        web_targets=["https://example.com", "https://example.com"],
        network_targets=["10.20.30.4", "10.20.30.4"],
    )

    loaded = load_engagement(save_engagement(original, tmp_path / "targets.yaml"))

    assert loaded.web_targets == ["https://example.com"]
    assert loaded.network_targets == ["10.20.30.4"]


@pytest.mark.parametrize(
    ("field", "target"),
    [
        ("web_targets", "https://outside.test"),
        ("web_targets", "https://admin.example.com"),
        ("network_targets", "10.20.31.4"),
        ("network_targets", "10.20.30.0/23"),
        ("network_targets", "https://example.com/path"),
    ],
)
def test_engagement_rejects_saved_targets_outside_scope(field, target):
    with pytest.raises(ValueError, match="saved .* target"):
        _engagement(**{field: [target]})


def test_engagement_accepts_wildcard_hosts_and_ip_web_targets():
    engagement = _engagement(
        web_targets=["https://api.example.com", "https://10.20.30.4"],
        network_targets=["api.example.com", "10.20.30.128/25"],
    )

    assert engagement.web_targets == ["https://api.example.com", "https://10.20.30.4"]


def test_engagement_denied_network_overrides_allowed_network():
    scope = {
        "allow_hosts": ["example.com"],
        "allow_networks": ["10.20.30.0/24"],
        "deny_networks": ["10.20.30.128/25"],
    }

    with pytest.raises(ValueError, match="overlaps denied scope"):
        _engagement(scope=scope, network_targets=["10.20.30.0/24"])


def test_engagement_summary_never_contains_header_values():
    engagement = _engagement()
    summary = engagement.redacted_summary()

    assert summary["configured_headers"] == ["X-Bug-Bounty"]
    assert "researcher-name" not in repr(summary)
    assert summary["user_agent_configured"] is True


@pytest.mark.parametrize(
    "scope",
    [
        {},
        {"allow_hosts": ["https://example.com/path"]},
        {"allow_networks": ["not-a-network"]},
        {"allow_hosts": ["example.com"], "allow_ports": [0]},
        {"allow_hosts": ["example.com"], "exclude_paths": ["admin/*"]},
    ],
)
def test_engagement_rejects_unsafe_or_ambiguous_scope(scope):
    with pytest.raises(ValueError):
        _engagement(scope=scope)


def test_engagement_rejects_header_injection():
    with pytest.raises(ValueError):
        _engagement(traffic={"headers": {"X-Test": "ok\r\nInjected: true"}})


def test_engagement_loader_rejects_unknown_fields(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        "schema_version: 1\nname: Test\nengagement_type: lab\n"
        "scope:\n  allow_hosts: [example.com]\nunexpected: true\n",
        encoding="utf-8",
    )

    with pytest.raises(EngagementError, match="unexpected"):
        load_engagement(path)


def test_engagement_slug_and_default_path_are_stable(tmp_path):
    assert engagement_slug("  Acme / External 2026 ") == "acme-external-2026"
    assert engagement_path("Acme External", tmp_path) == tmp_path / "acme-external.yaml"


def test_save_requires_yaml_extension(tmp_path):
    with pytest.raises(EngagementError, match=".yaml"):
        save_engagement(_engagement(), tmp_path / "engagement.json")
