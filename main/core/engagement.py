"""Versioned engagement configuration shared by every assessment domain."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
import os
from pathlib import Path
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import yaml

from main.core.scope import host_in_scope, target_host


ENGAGEMENT_SCHEMA = 1
ENGAGEMENTS_DIR = "engagements"
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class EngagementError(ValueError):
    """Raised when an engagement cannot be loaded or safely persisted."""


class EngagementScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow_hosts: list[str] = Field(default_factory=list)
    deny_hosts: list[str] = Field(default_factory=list)
    allow_networks: list[str] = Field(default_factory=list)
    deny_networks: list[str] = Field(default_factory=list)
    allow_ports: list[int] = Field(default_factory=list)
    deny_ports: list[int] = Field(default_factory=list)
    exclude_paths: list[str] = Field(default_factory=list)

    @field_validator("allow_hosts", "deny_hosts")
    @classmethod
    def validate_hosts(cls, values: list[str]) -> list[str]:
        normalized = []
        for raw in values:
            host = str(raw).strip().lower().rstrip(".")
            wildcard = host.startswith("*.")
            candidate = host[2:] if wildcard else host
            if not candidate or "://" in candidate or "/" in candidate:
                raise ValueError(f"host scope entries must be hostnames only: {raw!r}")
            if not all(_HOST_LABEL.fullmatch(label) for label in candidate.split(".")):
                raise ValueError(f"invalid hostname scope entry: {raw!r}")
            normalized.append(f"*.{candidate}" if wildcard else candidate)
        return list(dict.fromkeys(normalized))

    @field_validator("allow_networks", "deny_networks")
    @classmethod
    def validate_networks(cls, values: list[str]) -> list[str]:
        normalized = []
        for raw in values:
            try:
                normalized.append(str(ip_network(str(raw).strip(), strict=False)))
            except ValueError as exc:
                raise ValueError(f"invalid IP or CIDR scope entry: {raw!r}") from exc
        return list(dict.fromkeys(normalized))

    @field_validator("allow_ports", "deny_ports")
    @classmethod
    def validate_ports(cls, values: list[int]) -> list[int]:
        ports = sorted(set(values))
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("ports must be between 1 and 65535")
        return ports

    @field_validator("exclude_paths")
    @classmethod
    def validate_paths(cls, values: list[str]) -> list[str]:
        normalized = []
        for raw in values:
            path = str(raw).strip()
            if not path.startswith("/") or "://" in path:
                raise ValueError(f"excluded paths must begin with '/': {raw!r}")
            normalized.append(path)
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def require_authorized_scope(self):
        if not self.allow_hosts and not self.allow_networks:
            raise ValueError("at least one allowed host or network is required")
        return self


class TrafficPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    automation_allowed: bool = False
    max_requests_per_second: float | None = Field(default=None, gt=0, le=10000)
    user_agent: str | None = Field(default=None, max_length=512)
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("user_agent")
    @classmethod
    def validate_user_agent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value or "\n" in value or "\r" in value:
            raise ValueError("user agent must be a single non-empty line")
        return value

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, values: dict[str, str]) -> dict[str, str]:
        normalized = {}
        for raw_name, raw_value in values.items():
            name, value = str(raw_name).strip(), str(raw_value).strip()
            if not _HEADER_NAME.fullmatch(name):
                raise ValueError(f"invalid HTTP header name: {raw_name!r}")
            if not value or "\n" in value or "\r" in value:
                raise ValueError(f"header {name!r} must contain one non-empty line")
            normalized[name] = value
        return normalized


class Engagement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = ENGAGEMENT_SCHEMA
    name: str = Field(min_length=1, max_length=120)
    engagement_type: Literal["bug_bounty", "client", "internal", "lab"]
    mode: Literal["safe", "standard", "deep"] = "standard"
    scope: EngagementScope
    traffic: TrafficPolicy = Field(default_factory=TrafficPolicy)
    web_targets: list[str] = Field(default_factory=list)
    network_targets: list[str] = Field(default_factory=list)
    notes: str | None = Field(default=None, max_length=4000)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()
        if not value or any(character in value for character in "\r\n\0"):
            raise ValueError("engagement name must be a single non-empty line")
        return value

    @field_validator("web_targets", "network_targets")
    @classmethod
    def validate_targets(cls, values: list[str]) -> list[str]:
        normalized = []
        for raw in values:
            value = str(raw).strip()
            if not value or any(character in value for character in "\r\n\0"):
                raise ValueError("saved targets must contain one non-empty target per entry")
            normalized.append(value)
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def validate_saved_targets_against_scope(self):
        """Reject reusable targets that exceed the engagement authorization."""

        host_scope = {"allow": self.scope.allow_hosts, "deny": self.scope.deny_hosts}
        allowed_networks = [ip_network(value) for value in self.scope.allow_networks]
        denied_networks = [ip_network(value) for value in self.scope.deny_networks]

        for target in self.web_targets:
            host = target_host(target)
            if not host:
                raise ValueError("saved web target does not contain a valid host")
            try:
                address = ip_address(host)
            except ValueError:
                if not host_in_scope(host, host_scope):
                    raise ValueError(
                        f"saved web target host {host!r} is outside engagement scope"
                    )
            else:
                target_network = ip_network(address)
                if any(target_network.overlaps(network) for network in denied_networks):
                    raise ValueError(
                        f"saved web target address {host!r} overlaps denied scope"
                    )
                if not any(target_network.subnet_of(network) for network in allowed_networks):
                    raise ValueError(
                        f"saved web target address {host!r} is outside engagement scope"
                    )

        for target in self.network_targets:
            try:
                target_network = ip_network(target, strict=False)
            except ValueError:
                host = target_host(target)
                if (
                    not host
                    or host != target.lower().rstrip(".")
                    or not host_in_scope(host, host_scope)
                ):
                    raise ValueError(
                        f"saved network target {target!r} is invalid or outside engagement scope"
                    )
                continue

            if any(target_network.overlaps(network) for network in denied_networks):
                raise ValueError(
                    f"saved network target {target!r} overlaps denied scope"
                )
            if not any(target_network.subnet_of(network) for network in allowed_networks):
                raise ValueError(
                    f"saved network target {target!r} is outside engagement scope"
                )
        return self

    def web_scope(self) -> dict[str, list[str]]:
        """Return the host scope shape understood by the existing web runner."""

        return {"allow": self.scope.allow_hosts, "deny": self.scope.deny_hosts}

    def redacted_summary(self) -> dict:
        """Return useful policy metadata without disclosing header values."""

        return {
            "name": self.name,
            "engagement_type": self.engagement_type,
            "mode": self.mode,
            "automation_allowed": self.traffic.automation_allowed,
            "max_requests_per_second": self.traffic.max_requests_per_second,
            "user_agent_configured": self.traffic.user_agent is not None,
            "configured_headers": sorted(self.traffic.headers),
            "allowed_hosts": len(self.scope.allow_hosts),
            "allowed_networks": len(self.scope.allow_networks),
            "web_targets": len(self.web_targets),
            "network_targets": len(self.network_targets),
        }


def engagement_slug(name: str) -> str:
    """Build a stable filesystem-safe identifier from a display name."""

    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    if not slug:
        raise EngagementError("engagement name does not contain a usable identifier")
    return slug[:80]


def engagement_path(name: str, root: Path | None = None) -> Path:
    return (root or Path.cwd() / ENGAGEMENTS_DIR) / f"{engagement_slug(name)}.yaml"


def load_engagement(path: Path) -> Engagement:
    """Load and strictly validate one YAML engagement document."""

    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise EngagementError("engagement document must be a YAML mapping")
        return Engagement.model_validate(payload)
    except EngagementError:
        raise
    except Exception as exc:
        raise EngagementError(f"invalid engagement {path}: {exc}") from exc


def save_engagement(engagement: Engagement, path: Path | None = None) -> Path:
    """Atomically save an engagement with owner-only file permissions."""

    destination = path or engagement_path(engagement.name)
    if destination.suffix.lower() not in {".yaml", ".yml"}:
        raise EngagementError("engagement files must use .yaml or .yml")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    payload = engagement.model_dump(mode="json", exclude_none=True)
    temporary.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(destination)
    os.chmod(destination, 0o600)
    return destination.resolve()
