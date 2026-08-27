from pathlib import Path

import pytest

from main.core.scope import (
    ScopeError,
    filter_in_scope,
    host_in_scope,
    target_host,
    validate_targets,
)


def test_target_host_supports_bare_domains_and_urls():
    assert target_host("example.com") == "example.com"
    assert target_host("https://example.com/path") == "example.com"
    assert target_host("example.com/path") == "example.com"


def test_bare_out_of_scope_target_is_rejected(tmp_path):
    targets = tmp_path / "targets.txt"
    scope = tmp_path / "scope.yaml"
    targets.write_text("outside.example\n", encoding="utf-8")
    scope.write_text("allow:\n  - example.com\ndeny: []\n", encoding="utf-8")

    with pytest.raises(ScopeError, match="not in allow list"):
        validate_targets(targets, scope)


def test_downstream_scope_filter_rejects_external_and_relative_values():
    accepted, rejected = filter_in_scope(
        ["https://example.com/a", "https://third-party.test/x", "/relative"],
        {"allow": ["example.com"], "deny": []},
    )

    assert accepted == ["https://example.com/a"]
    assert rejected == ["https://third-party.test/x", "/relative"]


def test_explicit_wildcard_allows_subdomains_but_deny_takes_precedence():
    scope = {
        "allow": ["example.com", "*.example.com"],
        "deny": ["admin.example.com"],
    }

    assert host_in_scope("example.com", scope)
    assert host_in_scope("api.example.com", scope)
    assert not host_in_scope("admin.example.com", scope)
    assert not host_in_scope("unrelated.test", scope)


def test_empty_allowlist_fails_closed(tmp_path):
    scope = {"allow": [], "deny": []}

    assert not host_in_scope("example.com", scope)
    assert filter_in_scope(["https://example.com"], scope) == (
        [],
        ["https://example.com"],
    )

    targets = tmp_path / "targets.txt"
    scope_file = tmp_path / "scope.yaml"
    targets.write_text("example.com\n", encoding="utf-8")
    scope_file.write_text("allow: []\ndeny: []\n", encoding="utf-8")

    with pytest.raises(ScopeError, match="allow list is empty"):
        validate_targets(targets, scope_file)
