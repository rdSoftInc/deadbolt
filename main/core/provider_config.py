"""Optional provider credentials loaded without ever exposing secret values."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


PROVIDERS: dict[str, tuple[str, ...]] = {
    "shodan": ("SHODAN_API_KEY",),
    "censys": ("CENSYS_PAT",),
    "securitytrails": ("SECURITYTRAILS_API_KEY",),
    "virustotal": ("VIRUSTOTAL_API_KEY",),
    "chaos": ("CHAOS_KEY",),
    "projectdiscovery": ("PROJECTDISCOVERY_API_KEY",),
    "interactsh": ("INTERACTSH_SERVER", "INTERACTSH_TOKEN"),
}


@dataclass(frozen=True)
class ProviderStatus:
    name: str
    configured: bool
    configured_variables: tuple[str, ...]
    missing_variables: tuple[str, ...]


def _parse_env_file(path: Path) -> dict[str, str]:
    """Read simple KEY=VALUE entries; environment variables take precedence."""

    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value[:1] == value[-1:] and value[:1] in {'"', "'"}:
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def load_provider_environment(env_file: Path | None = None) -> dict[str, str]:
    """Return only recognized non-empty provider values for runner injection."""

    file_values = _parse_env_file(env_file or (Path.cwd() / ".env"))
    names = {name for required in PROVIDERS.values() for name in required}
    return {
        name: value
        for name in names
        if (value := os.environ.get(name, file_values.get(name, "")).strip())
    }


def provider_statuses(env_file: Path | None = None) -> list[ProviderStatus]:
    configured = load_provider_environment(env_file)
    statuses = []
    for provider, variables in PROVIDERS.items():
        present = tuple(name for name in variables if name in configured)
        missing = tuple(name for name in variables if name not in configured)
        statuses.append(ProviderStatus(provider, not missing, present, missing))
    return statuses


def environment_for_provider(provider: str, env_file: Path | None = None) -> dict[str, str]:
    """Return the minimum credential subset for one explicitly selected provider."""

    if provider not in PROVIDERS:
        raise ValueError(f"unknown provider: {provider}")
    values = load_provider_environment(env_file)
    return {name: values[name] for name in PROVIDERS[provider] if name in values}
