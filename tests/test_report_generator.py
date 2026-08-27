import json
from pathlib import Path

from main.report.generator import build_report_model, generate_report


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_reports_are_scope_aware_deduplicated_and_portable(tmp_path):
    run = tmp_path / "run_test"
    work = run / "work"
    work.mkdir(parents=True)
    raw = run / "raw" / "nuclei" / "nuclei.jsonl"
    raw.parent.mkdir(parents=True)
    raw.write_text("{}\n", encoding="utf-8")
    _write_json(run / "meta.json", {
        "run_id": "run_test", "domain": "web", "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00", "targets_file": str(work / "input.targets.txt"),
        "deadbolt_version": "1.2.0", "tools": {}, "errors": {},
    })
    records = [
        {"asset": "api.example.com", "title": "asset", "tool": "subfinder", "kind": "asset", "severity": "low", "timestamp": "2026-01-01T00:00:00Z", "evidence_path": str(run / "raw/subfinder.txt"), "metadata": {}},
        {"asset": "api.example.com", "title": "asset", "tool": "dnsx", "kind": "asset", "severity": "low", "timestamp": "2026-01-01T00:00:00Z", "evidence_path": str(run / "raw/dnsx.txt"), "metadata": {}},
        {"asset": "outside.test", "title": "asset", "tool": "subfinder", "kind": "asset", "severity": "low", "timestamp": "2026-01-01T00:00:00Z", "evidence_path": str(run / "raw/subfinder.txt"), "metadata": {}},
        {"asset": "example.com", "title": "XSS", "tool": "nuclei", "kind": "finding", "severity": "high", "template_id": "xss", "timestamp": "2026-01-01T00:00:00Z", "evidence_path": str(raw), "metadata": {"tool_severity": "medium", "verification_status": "Unverified"}},
    ]
    _write_json(run / "normalized" / "findings.json", records)
    _write_json(run / "normalized" / "nuclei.findings.json", [records[-1]])
    _write_json(run / "state.json", {"tools": {}})
    (work / "input.targets.txt").write_text("example.com\n", encoding="utf-8")
    (work / "scope.rejected.txt").write_text("outside.test\n", encoding="utf-8")

    model = build_report_model(run)
    assert len(model["surface"]) == 1
    assert model["surface"][0]["sources"] == ["subfinder", "dnsx"]
    assert len(model["excluded_surface"]) == 1
    assert model["findings"][0]["evidence"] == "raw/nuclei/nuclei.jsonl"
    assert model["findings"][0]["tool_severity"] == "medium"
    for stage in model["coverage"]:
        assert stage["value"] == len(stage["items"])

    generate_report(run)
    for name in ("technical-report.html", "stakeholder-report.html", "report.html"):
        assert (run / name).is_file()
    assert (run / "report.html").read_text() == (run / "technical-report.html").read_text()
    assert "outside.test" in (run / "technical-report.html").read_text()
    assert "outside.test" not in (run / "stakeholder-report.html").read_text()
    assert "Coverage inventory" in (run / "technical-report.html").read_text()
    assert "Assessment inventory" not in (run / "stakeholder-report.html").read_text()
    assert "Concise stakeholder report" in (run / "stakeholder-report.html").read_text()


def test_finding_worklist_is_an_auditable_index():
    from datetime import datetime, timezone
    from main.schema.normalize import Finding
    from main.utils.worklists import _findings_to_work_items

    finding = Finding(asset="example.com", title="Issue", tool="nuclei", kind="finding", severity="high", template_id="issue-id", timestamp=datetime.now(timezone.utc), evidence_path="raw.jsonl")
    assert _findings_to_work_items("findings", [finding]) == ["high\texample.com\tissue-id"]


def test_report_explains_route_quality_exclusions(tmp_path):
    run = tmp_path / "run_quality"
    work = run / "work"
    work.mkdir(parents=True)
    _write_json(run / "meta.json", {
        "run_id": "run_quality", "domain": "web",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "targets_file": str(work / "input.targets.txt"),
        "deadbolt_version": "1.2.0", "tools": {}, "errors": {},
    })
    _write_json(run / "normalized" / "findings.json", [
        {"asset": "https://example.com/20", "title": "path", "tool": "linkfinder", "kind": "path", "severity": "info", "metadata": {}},
    ])
    _write_json(run / "state.json", {"tools": {
        "nuclei": {
            "status": "done", "version": "3.11.1",
            "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": "2026-01-01T00:03:24.597000+00:00",
        },
        "ffuf": {
            "status": "not_applicable", "version": "2.2.1",
            "reason": "disabled by Safe mode", "output_file": "raw/ffuf/results.json",
        },
    }})
    _write_json(work / "enumeration.route-quality.json", [
        {"url": "https://example.com/client", "disposition": "candidate", "confidence": "low", "reason": "matches SPA soft-404 shell", "sources": ["katana"]},
        {"url": "https://example.com/CallExpression", "disposition": "rejected", "confidence": "high", "reason": "parser or syntax artifact", "sources": ["linkfinder"]},
        {"url": "https://example.com/20", "disposition": "rejected", "confidence": "high", "reason": "parser or syntax artifact", "sources": ["linkfinder"]},
    ])
    (work / "enumeration.routes.candidates.txt").write_text(
        "https://example.com/client\n", encoding="utf-8"
    )
    (work / "input.targets.txt").write_text("example.com\n", encoding="utf-8")

    model = build_report_model(run)

    assert len(model["route_candidates"]) == 1
    assert len(model["route_rejections"]) == 2
    assert not any(
        item["asset"] == "https://example.com/client"
        for item in model["surface"]
    )
    assert not any(item["asset"] == "https://example.com/20" for item in model["surface"])
    assert model["executions"][0]["duration"] == "3m 24s"
    assert model["executions"][1]["status_class"] == "neutral"
    assert "does not establish that no API surface exists" in model["api_inventory_note"]
    assert any("soft-404" in item for item in model["limitations"])
    generate_report(run)
    technical = (run / "technical-report.html").read_text(encoding="utf-8")
    assert "Route-quality exclusions" in technical
    assert "CallExpression" in technical
    attack_surface = technical.split("<h2>In-scope attack surface</h2>", 1)[1].split("<h2>Route-quality exclusions</h2>", 1)[0]
    assert "https://example.com/20" not in attack_surface
    assert 'class="neutral">NOT_APPLICABLE' in technical
    assert "disabled by Safe mode" in technical
    assert "3m 24s" in technical
    assert "API request inventory" in technical


def test_report_api_inventory_omits_static_bundle_noise_and_namespaces(tmp_path):
    run = tmp_path / "run_api_quality"
    work = run / "work"
    work.mkdir(parents=True)
    _write_json(run / "meta.json", {
        "run_id": "run_api_quality", "domain": "web",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "targets_file": str(work / "input.targets.txt"),
        "deadbolt_version": "1.2.0", "tools": {}, "errors": {},
    })
    _write_json(run / "normalized" / "findings.json", [])
    _write_json(run / "state.json", {"tools": {}})
    _write_json(work / "enumeration.api-inventory.json", {
        "schema_version": 1,
        "entries": [
            {
                "url": "https://example.com/api/login", "method": "POST",
                "raw_expression": 'config.apiBase + "/login"',
                "evidence_status": "observed", "confidence": "high",
                "scope_status": "in_scope", "source": "katana-browser",
                "provenance": [
                    {
                        "source": "deadbolt-js-static",
                        "raw_expression": 'config.apiBase + "/login"',
                    },
                    {
                        "source": "linkfinder",
                        "raw_expression": 'apiRoot + "/login"',
                    },
                ],
            },
            {"url": "https://example.com/auth/assets/application/vnd.do", "method": "GET", "evidence_status": "observed", "confidence": "high", "scope_status": "in_scope", "source": "katana-browser"},
            {"url": "https://example.com/auth/assets/app.js", "method": "GET", "evidence_status": "observed", "confidence": "high", "scope_status": "in_scope", "source": "katana-browser"},
            {"url": "http://www.w3.org/2000/svg", "evidence_status": "discovered", "confidence": "low", "scope_status": "unknown", "source": "javascript-string-discovery"},
        ],
    })

    model = build_report_model(run)

    assert [item["url"] for item in model["api_inventory"]] == [
        "https://example.com/api/login"
    ]
    assert model["api_inventory"][0]["raw_expressions"] == [
        'config.apiBase + "/login"', 'apiRoot + "/login"',
    ]

    generate_report(run)
    technical = (run / "technical-report.html").read_text(encoding="utf-8")
    assert "Resolved endpoint and raw expression" in technical
    assert "https://example.com/api/login" in technical
    assert 'config.apiBase + "/login"' in technical
    assert 'apiRoot + "/login"' in technical
