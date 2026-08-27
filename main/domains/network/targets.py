"""Canonical parsing and engagement scope enforcement for network targets."""

from dataclasses import dataclass
from ipaddress import collapse_addresses, ip_address, ip_network
from pathlib import Path
import re

from main.core.engagement import Engagement
from main.core.scope import host_in_scope


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class NetworkTargetError(ValueError):
    """Raised when network targets are malformed or outside authorization."""


@dataclass(frozen=True)
class NetworkTargetSet:
    values: tuple[str, ...]
    address_count: int
    hostnames: int
    networks: int


def _hostname(value: str) -> str | None:
    normalized = value.lower().rstrip(".")
    if not normalized or "://" in normalized or "/" in normalized or ":" in normalized:
        return None
    return normalized if all(_HOST_LABEL.fullmatch(label) for label in normalized.split(".")) else None


def parse_network_targets(path: Path) -> NetworkTargetSet:
    """Parse IPs, CIDRs, and hostnames without resolving or expanding them."""

    values = []
    hostnames = networks = 0
    parsed_networks = []
    errors = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            if "/" in value:
                network = ip_network(value, strict=False)
                canonical = str(network)
                parsed_networks.append(network)
                networks += 1
            else:
                address = ip_address(value)
                canonical = str(address)
                parsed_networks.append(ip_network(address))
        except ValueError:
            host = _hostname(value)
            if host is None:
                errors.append(f"line {line_number}: invalid IP, CIDR, or hostname {value!r}")
                continue
            canonical = host
            hostnames += 1
        if canonical not in values:
            values.append(canonical)
    if errors:
        raise NetworkTargetError("Invalid network targets:\n" + "\n".join(errors))
    if not values:
        raise NetworkTargetError("network targets file contains no usable targets")
    ipv4 = [network for network in parsed_networks if network.version == 4]
    ipv6 = [network for network in parsed_networks if network.version == 6]
    address_count = sum(
        network.num_addresses
        for family in (ipv4, ipv6)
        for network in collapse_addresses(family)
    ) + hostnames
    return NetworkTargetSet(tuple(values), address_count, hostnames, networks)


def enforce_network_scope(targets: NetworkTargetSet, engagement: Engagement) -> None:
    """Require every target to be wholly contained by the engagement scope."""

    allowed_networks = [ip_network(value) for value in engagement.scope.allow_networks]
    denied_networks = [ip_network(value) for value in engagement.scope.deny_networks]
    host_scope = {
        "allow": engagement.scope.allow_hosts,
        "deny": engagement.scope.deny_hosts,
    }
    violations = []
    for value in targets.values:
        try:
            target = ip_network(value, strict=False)
        except ValueError:
            if not host_in_scope(value, host_scope):
                violations.append(f"{value} is outside allowed hostname scope")
            continue
        if any(
            target.version == denied.version and target.overlaps(denied)
            for denied in denied_networks
        ):
            violations.append(f"{value} overlaps a denied network")
            continue
        if not allowed_networks or not any(
            target.version == allowed.version and target.subnet_of(allowed)
            for allowed in allowed_networks
        ):
            violations.append(f"{value} is not wholly contained by an allowed network")
    if violations:
        raise NetworkTargetError("Network scope violation:\n" + "\n".join(violations))
