# SPDX-License-Identifier: MIT
#
# -----------------------------------------------------------------------------
# @file runner.py
# @brief nuclei execution wrapper.
#
# This module defines the execution logic for nuclei using a containerized
# runtime. nuclei performs vulnerability scanning using template-based
# detection and produces newline-delimited JSON output.
#
# Author: Rolstan Robert D'souza
# Date: 2026
# -----------------------------------------------------------------------------

import tempfile
from pathlib import Path

import yaml

from main.core.provider_config import environment_for_provider
from main.core.tool_manifest import get_tool_config
from main.domains.web.profiles import WebScanProfile, capped_rate, normalize_web_profile, policy_for
from main.execution.docker import run_container


_SEVERITIES = ("info", "low", "medium", "high", "critical")
_SAFE_EXPOSURE_BUDGET = "3m"
_SAFE_AUTOMATIC_BUDGET = "12m"


def _severities_at_least(minimum: str, *, floor: str | None = None) -> str:
    """Return the complete Nuclei severity set at or above a threshold."""

    normalized = minimum.strip().lower()
    if normalized not in _SEVERITIES:
        raise ValueError(f"Unsupported Nuclei severity threshold: {minimum}")
    if floor is not None:
        normalized_floor = floor.strip().lower()
        if normalized_floor not in _SEVERITIES:
            raise ValueError(f"Unsupported Nuclei severity floor: {floor}")
        normalized = max(
            (normalized, normalized_floor),
            key=_SEVERITIES.index,
        )
    start = _SEVERITIES.index(normalized)
    return ",".join(_SEVERITIES[start:])


def _merge_jsonl(inputs: list[Path], output: Path) -> None:
    """Publish de-duplicated JSONL from bounded Safe scan passes."""

    seen: set[str] = set()
    lines: list[str] = []
    for source in inputs:
        if not source.is_file():
            continue
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
            value = line.strip()
            if value and value not in seen:
                seen.add(value)
                lines.append(value)
    output.write_text(
        "\n".join(lines) + ("\n" if lines else ""),
        encoding="utf-8",
    )


def _run_bounded_nuclei(**kwargs) -> None:
    """Treat Nuclei's own max-time shutdown as a completed bounded pass."""

    try:
        run_container(**kwargs)
    except RuntimeError as exc:
        message = str(exc)
        # Nuclei 3.11 implements -max-time as an internal graceful interrupt
        # and exits non-zero after writing its output and resume file. A real
        # Docker/template error does not contain this shutdown signature.
        if (
            "CTRL+C pressed: Exiting" in message
            and "Attempting graceful shutdown" in message
            and "Creating resume file:" in message
        ):
            return
        raise


def run_nuclei(
    targets: Path,
    output: Path,
    min_severity: str = "medium",
    *,
    profile: WebScanProfile | str = WebScanProfile.STANDARD,
    rate_limit: float | None = None,
):
    """
    Execute nuclei against target assets.

    ``min_severity`` is inclusive: medium runs medium, high, and critical
    templates. Safe mode uses two bounded passes instead of traversing the
    complete template catalog at a low request rate.
    """

    profile = normalize_web_profile(profile)
    policy = policy_for(profile)
    common_args = [
        "-l", "/targets.txt",
        "-jsonl",
        "-c", str(policy.nuclei_concurrency),
        "-rate-limit", str(capped_rate(policy.nuclei_rate, rate_limit)),
        "-timeout", str(policy.nuclei_timeout),
        "-retries", str(policy.nuclei_retries),
        "-disable-update-check",
    ]
    credentials = (
        {} if profile is WebScanProfile.SAFE
        else environment_for_provider("interactsh")
    )

    with tempfile.TemporaryDirectory(prefix="deadbolt-nuclei-") as temporary:
        mounts = {targets: "/targets.txt", output.parent: "/output"}
        if credentials:
            config = Path(temporary) / "config.yaml"
            config.write_text(
                yaml.safe_dump({
                    "interactsh-server": credentials.get("INTERACTSH_SERVER"),
                    "interactsh-token": credentials.get("INTERACTSH_TOKEN"),
                }),
                encoding="utf-8",
            )
            mounts[config] = "/deadbolt-config.yaml"
            common_args.extend(["-config", "/deadbolt-config.yaml"])

        image = get_tool_config("nuclei").image
        if profile is WebScanProfile.SAFE:
            # Safe previously walked roughly 6,000 templates at one request
            # per second. First cover generic high-impact exposures, then let
            # Nuclei select relevant templates from detected technologies.
            pass_dir = Path(temporary) / "passes"
            pass_dir.mkdir()
            mounts.pop(output.parent)
            mounts[pass_dir] = "/scan-output"
            exclusions = [
                "-exclude-tags", "fuzz,dast,headless,intrusive,bruteforce",
                "-no-interactsh",
                "-type", "http",
            ]
            baseline = pass_dir / "exposures.jsonl"
            automatic = pass_dir / "automatic.jsonl"
            _run_bounded_nuclei(
                image=image,
                args=common_args + exclusions + [
                    "-t", "http/exposures",
                    "-severity", _severities_at_least(min_severity, floor="high"),
                    "-max-time", _SAFE_EXPOSURE_BUDGET,
                    "-o", "/scan-output/exposures.jsonl",
                ],
                mounts=mounts,
            )
            _run_bounded_nuclei(
                image=image,
                args=common_args + exclusions + [
                    "-automatic-scan",
                    "-severity", _severities_at_least(min_severity),
                    "-max-time", _SAFE_AUTOMATIC_BUDGET,
                    "-o", "/scan-output/automatic.jsonl",
                ],
                mounts=mounts,
            )
            _merge_jsonl([baseline, automatic], output)
            return

        args = common_args + [
            "-severity", _severities_at_least(min_severity),
            "-o", "/output/nuclei.jsonl",
        ]
        if profile is WebScanProfile.DEEP:
            args.append("-dast")
        run_container(image=image, args=args, mounts=mounts)
