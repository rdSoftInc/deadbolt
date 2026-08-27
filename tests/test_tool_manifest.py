from pathlib import Path

import pytest
from pydantic import ValidationError

from main.core.tool_manifest import (
    MANIFEST_PATH,
    get_tool_config,
    get_tool_config_by_image,
    load_tool_manifest,
)
from main.domains.android.tool_registry import TOOL_REGISTRY as ANDROID_TOOLS
from main.domains.ios.tool_registry import TOOL_REGISTRY as IOS_TOOLS
from main.domains.web.tool_registry import TOOL_REGISTRY as WEB_TOOLS


PROJECT_ROOT = Path(__file__).parents[1]


def test_manifest_is_packaged_and_covers_every_physical_tool():
    manifest = load_tool_manifest()

    assert MANIFEST_PATH.is_file()
    assert manifest.schema_version == 1
    assert len(manifest.tools) >= 20
    assert {"web", "network", "android", "ios"} == {
        domain
        for config in manifest.tools.values()
        for domain in config.domains
    }

    nmap = get_tool_config("nmap")
    assert nmap.domains == ["network"]
    assert nmap.version == "7.991"
    assert nmap.source == "nmap"


def test_domain_registries_get_images_from_manifest():
    role_to_physical_tool = {
        "httpx_paths": "httpx",
    }

    for registry in (WEB_TOOLS, ANDROID_TOOLS, IOS_TOOLS):
        for role, spec in registry.items():
            physical_tool = role_to_physical_tool.get(role, role)
            assert spec.image == get_tool_config(physical_tool).image


def test_managed_dockerfiles_consume_the_manifest_build_arg():
    for config in load_tool_manifest().tools.values():
        if not config.managed:
            continue

        dockerfile = PROJECT_ROOT / config.dockerfile
        assert dockerfile.is_file(), config.name
        contents = dockerfile.read_text(encoding="utf-8")
        assert f"ARG {config.build_arg}" in contents, config.name
        assert f"${{{config.build_arg}}}" in contents, config.name


def test_dnsx_uses_image_label_because_upstream_cli_version_is_stale():
    config = get_tool_config("dnsx")
    dockerfile = PROJECT_ROOT / config.dockerfile

    assert config.version_detection == "image_label"
    assert 'io.deadbolt.tool.version="${TOOL_VERSION}"' in dockerfile.read_text(encoding="utf-8")


def test_tlsx_uses_image_label_when_cli_embeds_a_stale_version():
    config = get_tool_config("tlsx")
    dockerfile = PROJECT_ROOT / config.dockerfile

    assert config.version_detection == "image_label"
    assert 'io.deadbolt.tool.version="${TOOL_VERSION}"' in dockerfile.read_text(encoding="utf-8")


def test_tagged_external_image_resolves_to_manifest_entry():
    expected = get_tool_config("mobsf")
    config = get_tool_config_by_image(expected.image)

    assert config is not None
    assert config.name == "mobsf"
    assert config.display_version == expected.display_version


def test_invalid_commit_pin_fails_fast(tmp_path):
    invalid = tmp_path / "tools.yaml"
    invalid.write_text(
        """schema: 1
tools:
  example:
    domains: [web]
    image: deadbolt-example
    dockerfile: docker/example/Dockerfile
    build_arg: TOOL_COMMIT
    managed: true
    source: github
    repository: example/example
    version: abc1234
    version_type: commit
    version_detection: configured
""",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="40-character SHAs"):
        load_tool_manifest(invalid)


def test_unknown_tool_has_actionable_error():
    with pytest.raises(KeyError, match="Unknown Deadbolt tool"):
        get_tool_config("does-not-exist")
