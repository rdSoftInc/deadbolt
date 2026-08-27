"""Deterministic, scope-bound Nmap plans for authorized network assessments."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Literal

from main.core.engagement import Engagement
from main.domains.network.profiles import NetworkScanMode, normalize_network_mode


class NetworkPolicyError(ValueError):
    """Raised when an engagement cannot produce a safe scanner plan."""


@dataclass(frozen=True)
class NmapPhase:
    """One future Nmap invocation, represented without executing it."""

    name: str
    description: str
    arguments: tuple[str, ...]
    requires_raw_socket: bool = False

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["arguments"] = list(self.arguments)
        return payload


@dataclass(frozen=True)
class NmapPlan:
    mode: NetworkScanMode
    image: str
    input_paths: tuple[str, ...]
    phases: tuple[NmapPhase, ...]
    effective_ports: tuple[int, ...] | None
    excluded_ports: tuple[int, ...]
    max_rate: float
    nse_scripts: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "scanner": "nmap",
            "mode": self.mode.value,
            "image": self.image,
            "input_paths": list(self.input_paths),
            "effective_ports": list(self.effective_ports) if self.effective_ports else None,
            "excluded_ports": list(self.excluded_ports),
            "max_rate": self.max_rate,
            "nse_scripts": list(self.nse_scripts),
            "phases": [phase.to_dict() for phase in self.phases],
        }


_DEFAULT_MAX_RATE = {
    NetworkScanMode.SAFE: 10.0,
    NetworkScanMode.STANDARD: 100.0,
    NetworkScanMode.DEEP: 500.0,
}

_STANDARD_NSE = ("banner", "http-title", "ssl-cert", "ssh-hostkey")
_DEEP_NSE = (
    "banner", "http-title", "http-headers", "http-methods", "ssl-cert",
    "ssh-hostkey", "smb2-security-mode", "smb2-time",
)


def _number(value: float) -> str:
    return str(int(value)) if value.is_integer() else format(value, "g")


def _ports(values: tuple[int, ...]) -> str:
    return ",".join(str(value) for value in values)


def _scope_arguments(engagement: Engagement, default_selection: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[int, ...] | None, tuple[int, ...]]:
    allowed = set(engagement.scope.allow_ports)
    denied = set(engagement.scope.deny_ports)
    if allowed:
        effective = tuple(sorted(allowed - denied))
        if not effective:
            raise NetworkPolicyError("all explicitly allowed network ports are denied")
        # -Pn prevents Nmap's implicit TCP discovery probes from escaping a
        # narrowly declared port boundary.
        return ("-Pn", "-p", _ports(effective)), effective, tuple(sorted(denied))
    arguments = list(default_selection)
    if denied:
        arguments.extend(("--exclude-ports", _ports(tuple(sorted(denied)))))
    return tuple(arguments), None, tuple(sorted(denied))


def build_nmap_plan(
    engagement: Engagement,
    mode: NetworkScanMode | str,
    *,
    image: str = "deadbolt-nmap",
    input_path: str = "/deadbolt/work/input.network-targets.txt",
    address_family: Literal[4, 6] = 4,
    phase_suffix: str = "",
) -> NmapPlan:
    """Compile an auditable Nmap plan without running a process or resolving targets."""

    selected = normalize_network_mode(mode)
    if not engagement.traffic.automation_allowed:
        raise NetworkPolicyError("engagement does not authorize automated scanning")
    ceiling = engagement.traffic.max_requests_per_second
    rate = min(_DEFAULT_MAX_RATE[selected], ceiling) if ceiling is not None else _DEFAULT_MAX_RATE[selected]
    if not math.isfinite(rate) or rate <= 0:
        raise NetworkPolicyError("network rate ceiling must be a positive finite number")

    family = ("-6",) if address_family == 6 else ()
    output_suffix = "-ipv6" if address_family == 6 else ""
    shared = (
        "-n", "--reason", "--open", "--noninteractive", "--stats-every", "5s",
        "--max-rate", _number(rate), *family, "-iL", input_path,
    )
    if selected is NetworkScanMode.SAFE:
        nse_scripts: tuple[str, ...] = ()
        scoped, effective, excluded = _scope_arguments(engagement, ("--top-ports", "100"))
        phases = (
            NmapPhase(
                f"tcp_inventory{phase_suffix}",
                "Conservative TCP connect inventory without scripts or version probes",
                ("--unprivileged", "-sT", "-T2", *scoped, *shared, "-oX", f"/deadbolt/raw/nmap-tcp{output_suffix}.xml"),
            ),
        )
    elif selected is NetworkScanMode.STANDARD:
        nse_scripts = _STANDARD_NSE
        scoped, effective, excluded = _scope_arguments(engagement, ("--top-ports", "1000"))
        phases = (
            NmapPhase(
                f"tcp_services{phase_suffix}",
                "TCP connect inventory with light service detection and curated evidence scripts",
                (
                    "--unprivileged", "-sT", "-sV", "--version-light",
                    "--script", ",".join(nse_scripts), "--script-timeout", "30s",
                    "-T3", *scoped, *shared, "-oX", f"/deadbolt/raw/nmap-tcp{output_suffix}.xml",
                ),
            ),
        )
    else:
        nse_scripts = _DEEP_NSE
        scoped, effective, excluded = _scope_arguments(engagement, ("-p-",))
        phases = (
            NmapPhase(
                f"tcp_services_os{phase_suffix}",
                "Full TCP SYN inventory with service, OS, and curated evidence scripts",
                (
                    "--privileged", "-sS", "-sV", "--version-all", "-O",
                    "--script", ",".join(nse_scripts), "--script-timeout", "60s",
                    "-T3", *scoped, *shared, "-oX", f"/deadbolt/raw/nmap-tcp{output_suffix}.xml",
                ),
                requires_raw_socket=True,
            ),
            NmapPhase(
                f"udp_inventory{phase_suffix}",
                "UDP inventory limited to authorized ports or the top 100 ports",
                (
                    "--privileged", "-sU", "-sV", "--version-light", "-T3",
                    *(_scope_arguments(engagement, ("--top-ports", "100"))[0]),
                    *shared, "-oX", f"/deadbolt/raw/nmap-udp{output_suffix}.xml",
                ),
                requires_raw_socket=True,
            ),
        )
    return NmapPlan(selected, image, (input_path,), phases, effective, excluded, rate, nse_scripts)
