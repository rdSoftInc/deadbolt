"""Load and validate Deadbolt's central scanner inventory."""

from functools import lru_cache
from pathlib import Path
from typing import Dict, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Domain = Literal["web", "network", "android", "ios"]
VersionType = Literal["release", "commit"]
VersionDetection = Literal["cli", "configured", "image_label"]


class ToolConfig(BaseModel):
    """Declarative lifecycle configuration for one physical scanner."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    domains: list[Domain]
    image: str
    dockerfile: str | None = None
    build_arg: str | None = None
    managed: bool
    source: Literal["github", "nmap"]
    repository: str
    version: str
    version_type: VersionType
    version_detection: VersionDetection = "cli"
    version_args: list[list[str]] = Field(default_factory=list)

    @field_validator("domains")
    @classmethod
    def unique_domains(cls, value: list[Domain]) -> list[Domain]:
        if not value or len(value) != len(set(value)):
            raise ValueError("domains must be non-empty and unique")
        return value

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        value = value.strip().lstrip("v")
        if not value:
            raise ValueError("version cannot be empty")
        return value

    @model_validator(mode="after")
    def validate_management(self):
        if self.managed and not self.dockerfile:
            raise ValueError("managed tools require a dockerfile")
        if self.managed and not self.build_arg:
            raise ValueError("managed tools require a build_arg")
        if not self.managed and self.dockerfile:
            raise ValueError("externally managed tools cannot define a dockerfile")
        if not self.managed and self.build_arg:
            raise ValueError("externally managed tools cannot define a build_arg")
        if self.version_detection == "cli" and not self.version_args:
            raise ValueError("CLI version detection requires version_args")
        if self.version_type == "commit":
            if len(self.version) != 40 or any(c not in "0123456789abcdef" for c in self.version.lower()):
                raise ValueError("commit versions must be full 40-character SHAs")
        return self

    @property
    def display_version(self) -> str:
        return self.version[:7] if self.version_type == "commit" else self.version

    @property
    def versioned_image(self) -> str:
        """Return the immutable local image alias for this configured pin."""

        repository = self.image.rsplit(":", 1)[0] if ":" in self.image else self.image
        return f"{repository}:{self.display_version}"

    @property
    def current_image(self) -> str:
        """Return the convenient moving alias for the active manifest pin."""

        repository = self.image.rsplit(":", 1)[0] if ":" in self.image else self.image
        return f"{repository}:current"


class ToolManifest(BaseModel):
    """Validated root model for the scanner inventory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = Field(alias="schema")
    tools: Dict[str, ToolConfig]


MANIFEST_PATH = Path(__file__).parents[1] / "config" / "tools.yaml"


@lru_cache(maxsize=1)
def load_tool_manifest(path: Path | None = None) -> ToolManifest:
    """Load the packaged tool manifest, failing fast on invalid configuration."""

    manifest_path = (path or MANIFEST_PATH).resolve()
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("tools"), dict):
        raise ValueError(f"Invalid tool manifest structure: {manifest_path}")

    raw["tools"] = {
        name: {"name": name, **config}
        for name, config in raw["tools"].items()
    }
    manifest = ToolManifest.model_validate(raw)

    images: dict[str, str] = {}
    for name, config in manifest.tools.items():
        if config.image in images:
            raise ValueError(
                f"Tool image {config.image!r} is shared by {images[config.image]!r} and {name!r}"
            )
        images[config.image] = name

    return manifest


def get_tool_config(name: str) -> ToolConfig:
    """Return one configured tool or raise a useful error."""

    try:
        return load_tool_manifest().tools[name]
    except KeyError as exc:
        raise KeyError(f"Unknown Deadbolt tool: {name}") from exc


def get_tool_config_by_image(image: str) -> ToolConfig | None:
    """Resolve a tool from either its exact image or untagged repository."""

    repository = image.split(":", 1)[0]
    for config in load_tool_manifest().tools.values():
        if config.image == image or config.image.split(":", 1)[0] == repository:
            return config
    return None
