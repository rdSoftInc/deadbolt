"""Network assessment modes shared by the CLI and future scanner pipeline."""

from enum import Enum


class NetworkScanMode(str, Enum):
    SAFE = "safe"
    STANDARD = "standard"
    DEEP = "deep"


MODE_DESCRIPTIONS = {
    NetworkScanMode.SAFE: "Top-100 TCP inventory at a conservative rate",
    NetworkScanMode.STANDARD: "Top-1000 TCP inventory with light service detection",
    NetworkScanMode.DEEP: "Full TCP plus top UDP, service, and OS detection",
}


def normalize_network_mode(value: NetworkScanMode | str) -> NetworkScanMode:
    return value if isinstance(value, NetworkScanMode) else NetworkScanMode(value)
