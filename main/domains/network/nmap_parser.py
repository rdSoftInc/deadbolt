"""Defensive Nmap XML normalization for network inventory and findings."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from main.schema.normalize import Finding


class NmapParseError(ValueError):
    """Raised when a raw Nmap artifact is unsafe or malformed."""


_VULNERABLE = re.compile(r"^\s*(?:\|[_ ]*)?VULNERABLE\b", re.IGNORECASE | re.MULTILINE)
_HTTP_RESPONSE = re.compile(r"\bHTTP/\d(?:\.\d)?\s+\d{3}\b", re.IGNORECASE)
_MAX_XML_BYTES = 512 * 1024 * 1024
_REVIEW_SERVICES = {
    "ftp": "Cleartext file transfer",
    "telnet": "Cleartext remote administration",
    "rlogin": "Legacy cleartext remote administration",
    "rexec": "Legacy remote command service",
    "vnc": "Remote desktop service",
    "ms-wbt-server": "Remote desktop service",
    "snmp": "Network management service",
    "microsoft-ds": "SMB file-sharing service",
    "netbios-ssn": "NetBIOS/SMB service",
}


def _script(element: ET.Element) -> dict:
    return {
        "id": element.get("id", "unknown"),
        "output": element.get("output", ""),
    }


def _service_asset(host: str, protocol: str, port: int) -> str:
    displayed = f"[{host}]" if ":" in host else host
    return f"{displayed}:{port}/{protocol}"


def _parse_host(element: ET.Element, source: Path) -> dict:
    status = element.find("status")
    addresses = [
        {"address": item.get("addr", ""), "type": item.get("addrtype", "unknown"), "vendor": item.get("vendor")}
        for item in element.findall("address")
        if item.get("addr")
    ]
    hostnames = sorted({
        item.get("name", "").lower().rstrip(".")
        for item in element.findall("./hostnames/hostname")
        if item.get("name")
    })
    primary = next(
        (item["address"] for family in ("ipv4", "ipv6") for item in addresses if item["type"] == family),
        hostnames[0] if hostnames else "unknown",
    )
    services = []
    scripts = []
    for port in element.findall("./ports/port"):
        state = port.find("state")
        service = port.find("service")
        protocol = port.get("protocol", "unknown")
        port_number = int(port.get("portid", "0"))
        record = {
            "host": primary,
            "protocol": protocol,
            "port": port_number,
            "state": state.get("state", "unknown") if state is not None else "unknown",
            "reason": state.get("reason") if state is not None else None,
            "service": service.get("name") if service is not None else None,
            "product": service.get("product") if service is not None else None,
            "version": service.get("version") if service is not None else None,
            "extra_info": service.get("extrainfo") if service is not None else None,
            "tunnel": service.get("tunnel") if service is not None else None,
            "method": service.get("method") if service is not None else None,
            "confidence": int(service.get("conf", "0")) if service is not None else 0,
            "cpes": [item.text for item in service.findall("cpe") if item.text] if service is not None else [],
            "source": str(source),
        }
        port_scripts = [
            {**_script(item), "host": primary, "protocol": protocol, "port": port_number, "source": str(source)}
            for item in port.findall("script")
        ]
        fingerprint = next(
            (
                item for item in port_scripts
                if item["id"] == "fingerprint-strings" and _HTTP_RESPONSE.search(item["output"])
            ),
            None,
        )
        if fingerprint and record["method"] != "probed":
            record["original_service"] = record["service"]
            record["service"] = "http"
            record["method"] = "fingerprint-inferred"
            record["confidence"] = max(record["confidence"], 7)
        services.append(record)
        scripts.extend(port_scripts)
    for item in element.findall("./hostscript/script"):
        scripts.append({**_script(item), "host": primary, "protocol": None, "port": None, "source": str(source)})
    os_matches = []
    for match in element.findall("./os/osmatch"):
        classes = []
        for item in match.findall("osclass"):
            classes.append({
                "type": item.get("type"), "vendor": item.get("vendor"),
                "family": item.get("osfamily"), "generation": item.get("osgen"),
                "accuracy": int(item.get("accuracy", "0")),
                "cpes": [cpe.text for cpe in item.findall("cpe") if cpe.text],
            })
        os_matches.append({"name": match.get("name"), "accuracy": int(match.get("accuracy", "0")), "classes": classes})
    uptime = element.find("uptime")
    distance = element.find("distance")
    return {
        "primary_address": primary,
        "status": status.get("state", "unknown") if status is not None else "unknown",
        "status_reason": status.get("reason") if status is not None else None,
        "addresses": addresses,
        "hostnames": hostnames,
        "services": services,
        "os_matches": os_matches,
        "scripts": scripts,
        "uptime_seconds": int(uptime.get("seconds", "0")) if uptime is not None else None,
        "distance": int(distance.get("value", "0")) if distance is not None else None,
        "sources": [str(source)],
    }


def _load_xml(path: Path, evidence: Path | None = None) -> tuple[dict, list[dict]]:
    if not path.is_file():
        raise NmapParseError(f"Nmap XML artifact is missing: {path}")
    if path.stat().st_size > _MAX_XML_BYTES:
        raise NmapParseError(f"Nmap XML exceeds the 512 MiB safety limit: {path}")
    with path.open("rb") as stream:
        carry = b""
        for chunk in iter(lambda: stream.read(65536), b""):
            inspected = (carry + chunk).upper()
            without_inert_nmap_doctype = re.sub(
                br"<!DOCTYPE\s+NMAPRUN\s*>", b"", inspected
            )
            if b"<!DOCTYPE" in without_inert_nmap_doctype or b"<!ENTITY" in inspected:
                raise NmapParseError(f"DTD/entity declarations are not accepted in Nmap XML: {path}")
            carry = inspected[-16:]
    try:
        context = ET.iterparse(path, events=("start", "end"))
        _, root = next(context)
    except ET.ParseError as exc:
        raise NmapParseError(f"Malformed Nmap XML {path}: {exc}") from exc
    except StopIteration as exc:
        raise NmapParseError(f"Empty Nmap XML artifact: {path}") from exc
    if root.tag != "nmaprun":
        raise NmapParseError(f"Unexpected XML root in {path}: {root.tag}")
    evidence_path = evidence or path
    metadata = {
        "source": str(evidence_path),
        "scanner": root.get("scanner"),
        "version": root.get("version"),
        "arguments": root.get("args"),
        "started_epoch": int(root.get("start", "0")) or None,
        "finished_epoch": None,
        "exit": None,
    }
    hosts = []
    try:
        for event, element in context:
            if event != "end":
                continue
            if element.tag == "host":
                hosts.append(_parse_host(element, evidence_path))
                element.clear()
            elif element.tag == "finished":
                metadata["finished_epoch"] = int(element.get("time", "0")) or None
                metadata["exit"] = element.get("exit")
    except ET.ParseError as exc:
        raise NmapParseError(f"Malformed Nmap XML {path}: {exc}") from exc
    return metadata, hosts


def normalize_nmap_outputs(run_dir: Path, xml_paths: list[Path]) -> dict:
    """Merge Nmap XML artifacts and write portable normalized evidence."""

    scans = []
    merged: dict[str, dict] = {}
    for path in xml_paths:
        try:
            evidence = path.resolve().relative_to(run_dir.resolve())
        except ValueError:
            evidence = Path(path.name)
        metadata, hosts = _load_xml(path, evidence)
        scans.append(metadata)
        for host in hosts:
            key = host["primary_address"]
            if key not in merged:
                merged[key] = host
                continue
            current = merged[key]
            current["hostnames"] = sorted(set(current["hostnames"] + host["hostnames"]))
            current["sources"] = sorted(set(current["sources"] + host["sources"]))
            current["addresses"] = list({(item["address"], item["type"]): item for item in current["addresses"] + host["addresses"]}.values())
            current["services"] = list({
                (item["protocol"], item["port"]): item
                for item in current["services"] + host["services"]
            }.values())
            current["scripts"] = list({
                (item["id"], item.get("protocol"), item.get("port")): item
                for item in current["scripts"] + host["scripts"]
            }.values())
            current["os_matches"] = sorted(
                {
                    (item.get("name"), item.get("accuracy")): item
                    for item in current["os_matches"] + host["os_matches"]
                }.values(),
                key=lambda item: item["accuracy"], reverse=True,
            )

    hosts = sorted(merged.values(), key=lambda item: item["primary_address"])
    services = sorted(
        [service for host in hosts for service in host["services"] if service["state"] in {"open", "open|filtered"}],
        key=lambda item: (item["host"], item["protocol"], item["port"]),
    )
    scripts = [item for host in hosts for item in host["scripts"]]
    os_observations = [
        {"host": host["primary_address"], **match}
        for host in hosts for match in host["os_matches"]
    ]
    review = []
    for service in services:
        reason = _REVIEW_SERVICES.get(str(service.get("service") or "").lower())
        if reason:
            review.append({**service, "review_reason": reason, "classification": "exposure_review"})

    timestamp = datetime.now(timezone.utc)
    records: list[Finding] = []
    for host in hosts:
        records.append(Finding(
            asset=host["primary_address"], title="Network host", tool="nmap", kind="asset",
            severity="info", timestamp=timestamp, evidence_path=host["sources"][0],
            metadata={
                "status": host["status"], "hostnames": host["hostnames"],
                "addresses": host["addresses"], "os_matches": host["os_matches"],
            },
        ))
    for service in services:
        name = service.get("service") or "unknown"
        records.append(Finding(
            asset=_service_asset(service["host"], service["protocol"], service["port"]),
            title=f"Open {service['protocol']} service: {name}", tool="nmap", kind="asset",
            severity="info", timestamp=timestamp, evidence_path=service["source"], metadata=service,
        ))
    for script in scripts:
        if not _VULNERABLE.search(script.get("output", "")):
            continue
        asset = (
            _service_asset(script["host"], script["protocol"], script["port"])
            if script.get("port") else script["host"]
        )
        records.append(Finding(
            asset=asset, title=f"Nmap script reported VULNERABLE: {script['id']}",
            tool="nmap", kind="finding", severity="high", template_id=f"nmap:{script['id']}",
            timestamp=timestamp, evidence_path=script["source"],
            metadata={
                "description": script.get("output", ""), "verification_status": "Unverified",
                "tool_severity": "high", "script_id": script["id"],
            },
        ))

    inventory = {
        "schema": 1,
        "summary": {
            "scans": len(scans), "hosts_observed": len(hosts),
            "hosts_up": sum(host["status"] == "up" for host in hosts),
            "open_services": len(services),
            "identified_services": sum(
                item.get("method") in {"probed", "fingerprint-inferred"} for item in services
            ),
            "os_candidates": len(os_observations), "script_observations": len(scripts),
            "vulnerability_signals": sum(record.kind == "finding" for record in records),
        },
        "scans": scans,
        "hosts": hosts,
        "services": services,
        "os_observations": os_observations,
        "scripts": scripts,
        "exposure_review": review,
    }
    normalized = run_dir / "normalized"
    normalized.mkdir(exist_ok=True)
    (normalized / "network-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    dumped = [record.model_dump(mode="json") for record in records]
    (normalized / "findings.json").write_text(json.dumps(dumped, indent=2) + "\n", encoding="utf-8")
    (normalized / "network-findings.json").write_text(
        json.dumps([item for item in dumped if item["kind"] == "finding"], indent=2) + "\n",
        encoding="utf-8",
    )
    return inventory
