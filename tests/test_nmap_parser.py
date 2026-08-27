import json

import pytest

from main.domains.network.nmap_parser import NmapParseError, normalize_nmap_outputs
from main.report.generator import build_report_model, generate_report
from main.domains.network.quality import NetworkQualityError, evaluate_network_quality


FIXTURE = __import__("pathlib").Path(__file__).parent / "fixtures" / "nmap-7.991.xml"


def _run(tmp_path):
    run = tmp_path / "run_network"
    raw = run / "raw"
    raw.mkdir(parents=True)
    xml = raw / "nmap-tcp.xml"
    xml.write_bytes(FIXTURE.read_bytes())
    (run / "state.json").write_text(json.dumps({
        "domain": "network",
        "targets": {"entries": 1},
        "engagement": {"snapshot": "scope/engagement.yaml", "hash": "abc123"},
        "tools": {"nmap": {"version": "7.991", "status": "complete", "phases": {
            "tcp_services_os": {
                "status": "complete", "duration_seconds": 10.0, "returncode": 0,
                "output_file": "raw/nmap-tcp.xml", "log_file": "logs/nmap.log",
            }
        }}},
    }), encoding="utf-8")
    (run / "meta.json").write_text(json.dumps({
        "run_id": "run_network", "domain": "network", "status": "complete",
        "started_at": "2026-08-17T16:30:00+00:00", "finished_at": "2026-08-17T16:31:00+00:00",
        "targets_file": str(run / "work/input.network-targets.txt"),
        "scan_profile": "deep", "deadbolt_version": "1.2.0", "errors": {},
    }), encoding="utf-8")
    return run, xml


def test_nmap_xml_normalizes_inventory_exposure_and_explicit_findings(tmp_path):
    run, xml = _run(tmp_path)

    inventory = normalize_nmap_outputs(run, [xml, xml])
    records = json.loads((run / "normalized" / "findings.json").read_text())

    assert inventory["summary"] == {
        "scans": 2, "hosts_observed": 1, "hosts_up": 1,
        "open_services": 3, "identified_services": 2, "os_candidates": 1,
        "script_observations": 1, "vulnerability_signals": 1,
    }
    assert inventory["hosts"][0]["hostnames"] == ["server.internal.example"]
    assert inventory["services"][0]["source"] == "raw/nmap-tcp.xml"
    assert len(inventory["exposure_review"]) == 2
    assert {item["kind"] for item in records} == {"asset", "finding"}
    finding = next(item for item in records if item["kind"] == "finding")
    assert finding["template_id"] == "nmap:example-vuln"
    assert finding["severity"] == "high"


def test_network_reports_include_real_inventory_without_calling_ports_vulnerabilities(tmp_path):
    run, xml = _run(tmp_path)
    normalize_nmap_outputs(run, [xml])

    model = build_report_model(run)
    generate_report(run)
    technical = (run / "technical-report.html").read_text()
    stakeholder = (run / "stakeholder-report.html").read_text()

    assert model["summary"]["open_services"] == 3
    assert "10.20.30.4" in technical
    assert "OpenSSH" in technical
    assert "cpe:/a:openbsd:openssh:9.6" in technical
    assert "Linux 5.X" in technical
    assert "Exposure review queue" in technical
    assert "Open ports alone are not counted as vulnerabilities" in technical
    assert "3</strong> open or potentially open services" in stakeholder
    assert "technical-report.html" in stakeholder


@pytest.mark.parametrize(
    "payload, message",
    [
        ("<notnmap/>", "Unexpected XML root"),
        ("<nmaprun><host>", "Malformed Nmap XML"),
        ("<!DOCTYPE nmaprun [<!ENTITY x 'bad'>]><nmaprun/>", "DTD/entity"),
    ],
)
def test_nmap_parser_rejects_untrusted_or_malformed_xml(tmp_path, payload, message):
    run = tmp_path / "run"
    raw = run / "raw"
    raw.mkdir(parents=True)
    xml = raw / "bad.xml"
    xml.write_text(payload)

    with pytest.raises(NmapParseError, match=message):
        normalize_nmap_outputs(run, [xml])


def test_nmap_parser_does_not_treat_not_vulnerable_as_a_finding(tmp_path):
    run = tmp_path / "run"
    raw = run / "raw"
    raw.mkdir(parents=True)
    xml = raw / "safe.xml"
    xml.write_text(
        "<nmaprun scanner='nmap' version='7.991'><host><status state='up'/>"
        "<address addr='127.0.0.1' addrtype='ipv4'/><hostscript>"
        "<script id='check' output='NOT VULNERABLE: patched'/></hostscript>"
        "</host><runstats><finished exit='success'/></runstats></nmaprun>"
    )

    inventory = normalize_nmap_outputs(run, [xml])

    assert inventory["summary"]["vulnerability_signals"] == 0


def test_nmap_parser_marks_http_fingerprint_inference_without_losing_table_guess(tmp_path):
    run = tmp_path / "run"
    raw = run / "raw"
    raw.mkdir(parents=True)
    xml = raw / "http.xml"
    xml.write_text(
        "<nmaprun scanner='nmap' version='7.991'><host><status state='up'/>"
        "<address addr='127.0.0.1' addrtype='ipv4'/><ports><port protocol='tcp' portid='3000'>"
        "<state state='open'/><service name='ppp' method='table' conf='3'/>"
        "<script id='fingerprint-strings' output='GetRequest: HTTP/1.1 200 OK'/></port>"
        "</ports></host><runstats><finished exit='success'/></runstats></nmaprun>"
    )

    inventory = normalize_nmap_outputs(run, [xml])
    service = inventory["services"][0]

    assert service["service"] == "http"
    assert service["original_service"] == "ppp"
    assert service["method"] == "fingerprint-inferred"
    assert inventory["summary"]["identified_services"] == 1


def test_network_quality_verifies_scope_and_grades_evidence(tmp_path):
    run, xml = _run(tmp_path)
    inventory = normalize_nmap_outputs(run, [xml])
    state = json.loads((run / "state.json").read_text())
    state["tools"]["nmap"]["plan"] = {
        "effective_ports": [22, 23, 161], "excluded_ports": []
    }
    state["run"] = {"mode": "deep"}

    quality = evaluate_network_quality(run, inventory, state)

    assert quality["scope_verified"] is True
    assert quality["grade"] == "complete"
    assert quality["metrics"]["service_identification_ratio"] == 0.667
    assert (run / "normalized" / "network-quality.json").is_file()


def test_network_quality_rejects_any_out_of_policy_service(tmp_path):
    run, xml = _run(tmp_path)
    inventory = normalize_nmap_outputs(run, [xml])
    state = json.loads((run / "state.json").read_text())
    state["tools"]["nmap"]["plan"] = {"effective_ports": [22], "excluded_ports": [23]}
    state["run"] = {"mode": "safe"}

    with pytest.raises(NetworkQualityError, match="port-scope verification failed"):
        evaluate_network_quality(run, inventory, state)
