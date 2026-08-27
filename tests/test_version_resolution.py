import pytest

from main.execution import latest_version
from main.execution.latest_version import COMMIT_TRACKED_IMAGES, REPO_MAP
from main.execution.version import get_tool_version


def test_pinned_mobsf_tag_is_reported_as_installed_version():
    image = "opensecurity/mobile-security-framework-mobsf:v4.5.1"

    assert get_tool_version(image) == "4.5.1"
    assert REPO_MAP[image.split(":", 1)[0]] == "MobSF/Mobile-Security-Framework-MobSF"


def test_external_image_version_comes_from_requested_tag():
    image = "opensecurity/mobile-security-framework-mobsf:v4.4.6"

    assert get_tool_version(image) == "4.4.6"


def test_dnsx_prefers_build_provenance_label(monkeypatch):
    class Result:
        returncode = 0
        stdout = "1.3.0\n"
        stderr = ""

    monkeypatch.setattr("main.execution.version.subprocess.run", lambda *args, **kwargs: Result())
    get_tool_version.cache_clear()

    assert get_tool_version("deadbolt-dnsx") == "1.3.0"


def test_reproducible_source_versions_use_short_commit_labels(monkeypatch):
    labels = {
        "deadbolt-hakrawler": "52a16fe61bd18b8f431b9d66058cba12e96e4451",
        "deadbolt-paramspider": "c44bdaae54789b237028e309b603d1aa5ad52e5e",
        "deadbolt-graphql-cop": "2b7e086efae672f28b419c7fcdfe6b48d846c9dc",
    }

    class Result:
        returncode = 0
        stderr = ""

        def __init__(self, stdout):
            self.stdout = stdout

    monkeypatch.setattr(
        "main.execution.version.subprocess.run",
        lambda command, **kwargs: Result(labels[command[3]]),
    )
    get_tool_version.cache_clear()

    assert get_tool_version("deadbolt-hakrawler") == "52a16fe"
    assert get_tool_version("deadbolt-paramspider") == "c44bdaa"
    assert get_tool_version("deadbolt-graphql-cop") == "2b7e086"
    assert {
        "deadbolt-hakrawler",
        "deadbolt-paramspider",
        "deadbolt-graphql-cop",
        "deadbolt-linkfinder",
    } <= COMMIT_TRACKED_IMAGES


def test_latest_release_resolution_uses_manifest_repository(monkeypatch):
    seen = []
    monkeypatch.setattr(
        latest_version,
        "_get_latest_release",
        lambda repository: seen.append(repository) or "9.9.9",
    )
    latest_version.get_latest_version.cache_clear()

    assert latest_version.get_latest_version("deadbolt-httpx") == "9.9.9"
    assert seen == ["projectdiscovery/httpx"]


def test_commit_tools_skip_release_lookup(monkeypatch):
    monkeypatch.setattr(
        latest_version,
        "_get_latest_release",
        lambda repository: pytest.fail("release lookup should not run"),
    )
    monkeypatch.setattr(
        latest_version,
        "_get_latest_commit",
        lambda repository: "52a16fe",
    )
    latest_version.get_latest_version.cache_clear()

    assert latest_version.get_latest_version("deadbolt-hakrawler") == "52a16fe"


def test_nmap_uses_its_official_stable_release_resolver(monkeypatch):
    monkeypatch.setattr(latest_version, "_get_latest_nmap_release", lambda: "7.991")
    monkeypatch.setattr(
        latest_version,
        "_get_latest_release",
        lambda repository: pytest.fail("Nmap must not use GitHub releases"),
    )
    latest_version.get_latest_version.cache_clear()
    latest_version.get_latest_pin.cache_clear()

    assert latest_version.get_latest_version("deadbolt-nmap") == "7.991"
    assert latest_version.get_latest_pin("deadbolt-nmap") == "7.991"


def test_two_component_nmap_cli_version_is_detected(monkeypatch):
    class Result:
        returncode = 0
        stdout = "Nmap version 7.991 ( https://nmap.org )\n"
        stderr = ""

    monkeypatch.setattr("main.execution.version.subprocess.run", lambda *args, **kwargs: Result())
    get_tool_version.cache_clear()

    assert get_tool_version("deadbolt-nmap") == "7.991"
