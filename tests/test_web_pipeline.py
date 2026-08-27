from datetime import datetime, timezone
from pathlib import Path
import json
import threading
from types import SimpleNamespace

from main.domains.web import runner
from main.schema.normalize import Finding
from main.tools.linkfinder import runner as linkfinder_runner
from main.tools.linkfinder.parser import parse_linkfinder
from main.tools.linkfinder.js_reconstruction import reconstruct_javascript_urls
from main.tools.ffuf import runner as ffuf_runner
from main.tools.katana import runner as katana_runner
from main.tools.katana.parser import parse_katana
from main.tools.httpx import runner as httpx_runner
from main.domains.web.profiles import WebScanProfile
from main.domains.web.tool_registry import TOOL_CATEGORIES
from main.core.tool_runtime import ToolRuntime


class FakeExecutionTable:
    def __init__(self):
        self.versions = {}
        self.latest_versions = {}
        self.update_status = {}

    def register_tool(self, name, version, update_status="pinned"):
        self.versions[name] = version
        self.update_status[name] = update_status

    def start(self):
        pass

    def stop(self):
        pass

    def tool_started(self, name):
        pass

    def tool_finished(self, name, findings):
        pass

    def tool_failed(self, name):
        pass

    def tool_cached(self, name, findings=None, duration_seconds=None):
        self.cached = getattr(self, "cached", [])
        self.cached.append((name, findings, duration_seconds))

    def tool_no_input(self, name):
        pass

    def tool_not_applicable(self, name):
        pass

    def tool_result_summary(self, name, summary):
        self.findings_summary = (name, summary)

    def _refresh(self):
        pass


def test_web_tools_have_simple_lifecycle_categories():
    assert set(TOOL_CATEGORIES.values()) == {"discover", "validate", "enumerate", "test"}
    assert TOOL_CATEGORIES["subfinder"] == "discover"
    assert TOOL_CATEGORIES["httpx"] == "validate"
    assert TOOL_CATEGORIES["arjun"] == "enumerate"
    assert TOOL_CATEGORIES["nuclei"] == "test"


def test_safe_profile_scans_nuclei_once_per_live_origin(tmp_path):
    live = tmp_path / "live.txt"
    routes = tmp_path / "routes.txt"

    assert runner._nuclei_target_sources(WebScanProfile.SAFE, live, routes) == [live]
    assert runner._nuclei_target_sources(WebScanProfile.STANDARD, live, routes) == [
        live,
        routes,
    ]
    assert runner._nuclei_target_sources(WebScanProfile.DEEP, live, routes) == [
        live,
        routes,
    ]


def test_direct_resume_defaults_to_preserved_state_scope(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    run = tmp_path / "outputs" / "run_20260404_070707"
    (run / "work").mkdir(parents=True)
    (run / "scope").mkdir()
    targets = run / "work" / "input.targets.txt"
    targets.write_text("secure.example.com\n", encoding="utf-8")
    snapshot = run / "scope" / "authorized.yaml"
    snapshot.write_text("allow:\n  - secure.example.com\ndeny: []\n", encoding="utf-8")
    (run / "state.json").write_text(__import__("json").dumps({
        "run": {"scan_profile": "safe", "local_lab": False},
        "scope": {"snapshot": "scope/authorized.yaml"},
        "tools": {},
    }), encoding="utf-8")
    checked = []

    def stop_after_scope_resolution(*, targets_file, scope_file):
        checked.append((targets_file, scope_file))
        raise RuntimeError("scope captured")

    monkeypatch.setattr(runner, "validate_targets", stop_after_scope_resolution)

    try:
        runner.run_web(str(targets), resume_from=run)
    except RuntimeError as exc:
        assert str(exc) == "scope captured"
    else:
        raise AssertionError("scope validation did not run")

    assert checked == [(targets, snapshot.resolve())]


def _finding(asset: str, tool: str, kind: str) -> Finding:
    return Finding(
        asset=asset,
        title=f"{tool} result",
        tool=tool,
        kind=kind,
        timestamp=datetime.now(timezone.utc),
        evidence_path="test",
    )


def test_web_pipeline_is_scoped_parallel_resumable_and_feeds_paths_to_nuclei(
    monkeypatch, tmp_path
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "scope.yaml").write_text(
        "allow:\n  - example.com\ndeny:\n  - outside.test\n",
        encoding="utf-8",
    )
    targets = tmp_path / "targets.txt"
    targets.write_text("example.com\n", encoding="utf-8")
    run_dir = tmp_path / "outputs" / "run_20260817_120000"
    monkeypatch.setattr(runner, "_resolve_run_base", lambda resume: run_dir)
    monkeypatch.setattr(runner, "ExecutionTable", FakeExecutionTable)
    monkeypatch.setattr(runner, "get_fresh_cached_versions", lambda image: ("test", "test"))
    monkeypatch.setattr(runner, "write_metadata", lambda **kwargs: None)
    monkeypatch.setattr(runner, "generate_report", lambda path: None)

    fanout = set(runner.ENUMERATION_FANOUT[:3])
    barrier = threading.Barrier(3)
    fanout_threads = set()
    nuclei_inputs = []
    calls = []

    def fake_run_tool(*, spec, table, input_file, base_dir, scan_profile):
        calls.append(spec.name)
        if spec.name in fanout:
            fanout_threads.add(threading.current_thread().name)
            barrier.wait(timeout=2)
        if spec.name == "subfinder":
            return [
                _finding("example.com", spec.name, "asset"),
                _finding("outside.test", spec.name, "asset"),
            ]
        if spec.name == "dnsx":
            return [_finding(value, spec.name, "asset") for value in input_file.read_text().splitlines()]
        if spec.name == "httpx":
            return [_finding("https://example.com", spec.name, "asset")]
        if spec.name == "katana":
            return [
                _finding("https://example.com/app", spec.name, "path"),
                _finding("https://outside.test/tracker", spec.name, "path"),
            ]
        if spec.name == "linkfinder":
            return [_finding("https://example.com/api", spec.name, "path")]
        if spec.name == "httpx_paths":
            results = []
            for value in input_file.read_text().splitlines():
                item = _finding(value, spec.name, "path")
                item.status_code = 200
                item.metadata = {
                    "content_type": "text/html",
                    "content_length": 999 if ".deadbolt-not-found-" in value else 100,
                }
                results.append(item)
            return results
        if spec.name == "nuclei":
            nuclei_inputs.extend(input_file.read_text().splitlines())
            return [_finding("https://example.com/app", spec.name, "finding")]
        return []

    monkeypatch.setattr(runner, "run_tool", fake_run_tool)
    runner.run_web(str(targets))

    assert len(fanout_threads) == 3
    assert nuclei_inputs == [
        "https://example.com",
        "https://example.com/app",
        "https://example.com/api",
    ]
    assert "https://outside.test/tracker" in (
        run_dir / "work" / "scope.rejected.txt"
    ).read_text(encoding="utf-8")
    for name in runner.ENUMERATION_FANOUT:
        assert (run_dir / "work" / "enumeration" / f"{name}.paths.txt").is_file()
    state = __import__("json").loads((run_dir / "state.json").read_text())
    snapshot = run_dir / state["scope"]["snapshot"]
    assert snapshot.is_file()
    assert state["scope"]["hash"] == runner.hash_file(snapshot)

    calls.clear()
    monkeypatch.setattr(
        runner,
        "run_tool",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("resume reran a tool")),
    )
    runner.run_web(str(targets), resume_from=run_dir)
    assert not calls
    payload = (run_dir / "normalized" / "findings.json").read_text(encoding="utf-8")
    assert "https://example.com/app" in payload
    assert '"kind": "asset"' in payload
    assert '"kind": "path"' in payload
    assert '"kind": "finding"' in payload


def test_linkfinder_resolves_relative_endpoints_against_javascript_origin(
    monkeypatch, tmp_path
):
    inputs = tmp_path / "paths.txt"
    output = tmp_path / "linkfinder.json"
    inputs.write_text("https://example.com/static/app.js\n", encoding="utf-8")

    class Result:
        returncode = 0
        stdout = "/api/v1\n//tracker.test/pixel\nhttps://example.com/rest/products\n"
        stderr = ""

    monkeypatch.setattr(linkfinder_runner.subprocess, "run", lambda *args, **kwargs: Result())
    monkeypatch.setattr(linkfinder_runner, "_fetch_javascript", lambda url: None)
    linkfinder_runner.run_linkfinder(inputs, output)

    payload = __import__("json").loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 3
    assert {
        (item["resolved_url"], item["raw_expression"], item["source_url"])
        for item in payload["endpoints"]
    } == {
        ("https://example.com/api/v1", "/api/v1", "https://example.com/static/app.js"),
        ("https://example.com/rest/products", "https://example.com/rest/products", "https://example.com/static/app.js"),
        ("https://tracker.test/pixel", "//tracker.test/pixel", "https://example.com/static/app.js"),
    }
    assert all(item["source_location"] is None for item in payload["endpoints"])
    assert [item.asset for item in parse_linkfinder(output)] == [
        "https://example.com/api/v1",
        "https://example.com/rest/products",
        "https://tracker.test/pixel",
    ]


def test_javascript_reconstruction_handles_base_template_and_cross_origin():
    fixture = Path(__file__).parent / "fixtures" / "javascript-url-construction.js"
    source = fixture.read_text(encoding="utf-8")

    results = reconstruct_javascript_urls(
        source, "https://secure.example.test/auth/assets/main.js"
    )
    resolved = {item.resolved_url: item for item in results}

    assert "https://secure.example.test/public/v1/PasswordLogin" in resolved
    assert "https://secure.example.test/public/v1/FederatedLogin" in resolved
    assert "https://itsme.example.test/status" in resolved
    assert "https://itsme.example.test/GetClockChallenge" in resolved
    assert all(item.source_location.startswith("line ") for item in results)
    assert not any("routeFromRuntime" in item.raw_expression for item in results)
    assert resolved["https://secure.example.test/public/v1/PasswordLogin"].method == "POST"
    assert resolved["https://secure.example.test/public/v1/PasswordLogin"].request_body_fields == (
        "accountId", "deviceId", "oneTimeCode",
    )
    assert resolved["https://secure.example.test/public/v1/FederatedLogin"].method == "POST"
    assert resolved["https://secure.example.test/public/v1/FederatedLogin"].request_body_fields == (
        "state", "code", "error", "errorDescription",
    )
    assert resolved["https://itsme.example.test/status"].method == "POST"
    assert resolved["https://itsme.example.test/GetClockChallenge"].method == "POST"


def test_javascript_reconstruction_resolves_minified_hostname_template_base_path():
    source = (
        'format("https://{prefix}secure.{company}.be/public",'
        '{prefix:env,company:tenant});'
        'request(ctx.publicProxy+"/v1/PasswordLogin",payload);'
        'request(config.publicProxy+"/v1/FederatedLogin",payload)'
    )

    results = reconstruct_javascript_urls(
        source, "https://secure.example.be/auth/assets/index.js"
    )
    resolved = {item.resolved_url: item for item in results}

    assert "https://secure.example.be/public/v1/PasswordLogin" in resolved
    assert "https://secure.example.be/public/v1/FederatedLogin" in resolved
    assert not any(item.method for item in results)


def test_javascript_reconstruction_resolves_cross_subdomain_template_origin():
    source = (
        'format("https://{prefix}itsme.{company}.be",'
        '{prefix:env,company:tenant});'
        'format("https://{prefix}secure.{company}.be/public",'
        '{prefix:env,company:tenant});'
        'request(context.itsme+"/GetClockChallenge",payload)'
    )

    results = reconstruct_javascript_urls(
        source, "https://secure.example.be/auth/assets/index.js"
    )

    challenge = next(
        item for item in results
        if item.resolved_url.endswith("/GetClockChallenge")
    )
    assert challenge.resolved_url == (
        "https://itsme.example.be/GetClockChallenge"
    )
    assert challenge.raw_expression == (
        'context.itsme+"/GetClockChallenge"'
    )
    assert challenge.method is None


def test_javascript_reconstruction_infers_minified_conditional_wrapper_methods():
    source = (
        'format("https://{prefix}itsme.{company}.be",{prefix:p,company:c}),'
        'format("https://{prefix}secure.{company}.be/public",{prefix:p,company:c}),'
        'md=async(e,n,t="same-origin")=>await(await fetch(e,{credentials:t,'
        'method:n?"POST":"GET",body:n?JSON.stringify(n):null})).json(),'
        'md(a.publicProxy+"/v1/PasswordLogin",payload,"include"),'
        'md(b.publicProxy+"/v1/FederatedLogin",callback,"include"),'
        'md(c.itsme+"/GetClockChallenge",challenge),'
        'md(c.itsme+"/health")'
    )

    results = reconstruct_javascript_urls(
        source, "https://secure.example.be/auth/assets/index.js"
    )
    resolved = {item.resolved_url: item for item in results}

    assert resolved[
        "https://secure.example.be/public/v1/PasswordLogin"
    ].method == "POST"
    assert resolved[
        "https://secure.example.be/public/v1/PasswordLogin"
    ].credentials_mode == "include"
    assert resolved[
        "https://secure.example.be/public/v1/FederatedLogin"
    ].method == "POST"
    assert resolved[
        "https://secure.example.be/public/v1/FederatedLogin"
    ].credentials_mode == "include"
    assert resolved[
        "https://itsme.example.be/GetClockChallenge"
    ].method == "POST"
    assert resolved[
        "https://itsme.example.be/GetClockChallenge"
    ].credentials_mode == "same-origin"
    assert resolved["https://itsme.example.be/health"].method == "GET"
    assert resolved["https://itsme.example.be/health"].credentials_mode == "same-origin"


def test_javascript_reconstruction_extracts_minified_wrapper_body_schemas():
    source = (
        'format("https://{prefix}itsme.{company}.be",{prefix:p,company:c}),' 
        'format("https://{prefix}secure.{company}.be/public",{prefix:p,company:c}),' 
        'mapLogin=e=>({accountId:e.userID,deviceId:e.serialNumber,'
        'oneTimeCode:e.challenge}),' 
        'md=async(e,n)=>await(await fetch(e,{method:n?"POST":"GET",'
        'body:n?JSON.stringify(n):null})).json(),'
        'md(a.publicProxy+"/v1/PasswordLogin",mapLogin(form)),'
        'md(b.publicProxy+"/v1/FederatedLogin",{state:s,code:c,error:e,'
        'errorDescription:d}),' 
        'md(c.itsme+"/GetClockChallenge",{localeId:l,'
        'deviceSerial:s,timestampChallenge:d})'
    )

    results = reconstruct_javascript_urls(
        source, "https://secure.example.be/auth/assets/index.js"
    )
    resolved = {item.resolved_url: item for item in results}

    assert resolved[
        "https://secure.example.be/public/v1/PasswordLogin"
    ].request_body_fields == (
        "accountId", "deviceId", "oneTimeCode",
    )
    assert resolved[
        "https://secure.example.be/public/v1/FederatedLogin"
    ].request_body_fields == (
        "state", "code", "error", "errorDescription",
    )
    assert resolved[
        "https://itsme.example.be/GetClockChallenge"
    ].request_body_fields == (
        "localeId", "deviceSerial", "timestampChallenge",
    )


def test_javascript_request_schema_records_types_and_requiredness_without_values():
    source = '''
    if (!username) throw new Error("required");
    fetch("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: username,
        rememberMe: true,
        attempts: 3,
        roles: ["user"],
        profile: {enabled: true}
      })
    });
    '''

    result = reconstruct_javascript_urls(source, "https://example.com/app.js")[0]
    schema = {field.name: field for field in result.request_body_schema}

    assert schema["username"].required is True
    assert schema["username"].data_type is None
    assert schema["rememberMe"].data_type == "boolean"
    assert schema["attempts"].data_type == "number"
    assert schema["roles"].data_type == "array"
    assert schema["profile"].data_type == "object"


def test_linkfinder_static_reconstruction_is_promoted_to_inferred(monkeypatch, tmp_path):
    inputs = tmp_path / "paths.txt"
    output = tmp_path / "linkfinder.json"
    inputs.write_text("https://example.com/assets/app.js\n", encoding="utf-8")
    source = 'const base = location.origin + "/public"; fetch(base + "/v1/login");'

    class Result:
        returncode = 0
        stdout = "/public/v1/login\n"
        stderr = ""

    monkeypatch.setattr(linkfinder_runner, "_fetch_javascript", lambda url: source)
    monkeypatch.setattr(linkfinder_runner.subprocess, "run", lambda *args, **kwargs: Result())
    linkfinder_runner.run_linkfinder(inputs, output)

    findings = parse_linkfinder(output)
    assert len(findings) == 1
    assert findings[0].metadata["evidence_status"] == "inferred"
    assert findings[0].metadata["confidence"] == "medium"
    assert findings[0].metadata["raw_expression"] == 'base + "/v1/login"'
    assert findings[0].metadata["source_location"].startswith("line ")


def test_javascript_wrapper_semantics_propagate_to_call_sites():
    fixture = Path(__file__).parent / "fixtures" / "javascript-request-wrappers.js"
    results = reconstruct_javascript_urls(
        fixture.read_text(encoding="utf-8"),
        "https://secure.example.test/auth/assets/main.js",
    )
    resolved = {item.resolved_url: item for item in results}

    login = resolved["https://secure.example.test/public/v1/PasswordLogin"]
    assert login.method == "POST"
    assert login.request_body_fields == (
        "accountId", "deviceId", "oneTimeCode",
    )
    assert login.request_header_names == ("Content-Type", "X-Client")
    assert login.credentials_mode == "include"
    assert login.wrapper_chain == ("md",)

    status = resolved["https://identity.example.test/status"]
    assert status.method == "POST"
    assert status.request_body_fields == ("state", "code")
    assert status.request_header_names == ("X-App-Version",)
    assert status.credentials_mode == "include"
    assert status.wrapper_chain == ("postJson",)

    runtime = resolved["https://secure.example.test/public/v1/runtime"]
    assert runtime.method is None
    assert runtime.wrapper_chain == ("md",)


def test_javascript_extracts_chained_response_fields_and_bounded_validation():
    source = '''
    if (!accountId) throw new Error("required");
    if (oneTimeCode.length < 6) throw new Error("short");
    fetch("/public/v1/login", {
      method: "POST",
      body: JSON.stringify({accountId, oneTimeCode})
    }).then(response => response.json()).then(data => {
      if (data.invalidCredentials || data.locked) showError();
    });
    '''

    result = reconstruct_javascript_urls(
        source, "https://secure.example.test/auth/assets/main.js"
    )[0]

    assert result.response_fields == ("invalidCredentials", "locked")
    assert result.client_validation_rules == (
        "accountId: required/empty check",
        "oneTimeCode: length check",
    )


def test_api_inventory_keeps_inferred_method_and_body_schema(tmp_path):
    endpoint = "https://example.com/public/v1/PasswordLogin"
    item = _finding(endpoint, "linkfinder", "path")
    item.metadata = {
        "evidence_status": "inferred",
        "confidence": "medium",
        "method": "POST",
        "methods": ["POST"],
        "request_body_fields_by_method": {
            "POST": ["accountId", "deviceId", "oneTimeCode"],
        },
        "request_body_schema": [
            {
                "name": "accountId",
                "data_type": "string",
                "required": True,
                "source": "JavaScript request object",
            },
        ],
        "request_header_names": ["Content-Type", "X-Client"],
        "credentials_mode": "include",
        "wrapper_chain": ["md"],
        "raw_expression": 'publicProxy + "/v1/PasswordLogin"',
        "source_url": "https://example.com/assets/app.js",
        "source_location": "line 42",
        "extractor": "deadbolt-js-static",
    }

    inventory = runner._write_api_inventory(
        [item], tmp_path, {"allow": ["example.com"], "deny": []}
    )

    assert len(inventory) == 1
    assert inventory[0]["method"] == "POST"
    assert inventory[0]["evidence_status"] == "inferred"
    assert inventory[0]["confidence"] == "medium"
    assert [field["name"] for field in inventory[0]["request_body_fields"]] == [
        "accountId", "deviceId", "oneTimeCode",
    ]
    assert inventory[0]["request_body_fields"][0] == {
        "name": "accountId",
        "location": "body",
        "data_type": "string",
        "required": True,
        "source": "JavaScript request object",
    }
    assert inventory[0]["request_header_names"] == ["Content-Type", "X-Client"]
    assert inventory[0]["credentials_mode"] == "include"
    assert inventory[0]["wrapper_chain"] == ["md"]


def test_linkfinder_rejects_static_registry_and_locale_artifacts(tmp_path):
    raw = tmp_path / "linkfinder.json"
    raw.write_text(
        __import__("json").dumps({
            "endpoints": [
                "https://example.com/auth/assets/application/json",
                "https://example.com/auth/assets/zh/SpelloutRules/spellout-cardinal",
                "https://example.com/auth/js/MEYCIQCg5A5XI/jejBzfqCLSey93aC3gSOSRa7F",
                "https://example.com/auth/binaries/installer-2.9.0.zip",
                "https://example.com/icons/favicon-32x32.png",
                "https://example.com/0123456789abcdef0123456789abcdef",
                "https://example.com/api/v1/assets/42",
                "https://example.com/auth/itsme/succeeded",
                "https://example.com/auth/resources.json?v=40.0.3",
                "https://example.com/GetClockChallenge",
            ]
        }),
        encoding="utf-8",
    )

    assert [item.asset for item in parse_linkfinder(raw)] == [
        "https://example.com/GetClockChallenge",
        "https://example.com/api/v1/assets/42",
        "https://example.com/auth/itsme/succeeded",
        "https://example.com/auth/resources.json?v=40.0.3",
    ]


def test_linkfinder_preserves_duplicate_bundle_contexts(tmp_path):
    raw = tmp_path / "linkfinder.json"
    raw.write_text(
        __import__("json").dumps({
            "schema_version": 2,
            "endpoints": [
                {
                    "resolved_url": "https://example.com/api/login",
                    "raw_expression": "/api/login",
                    "source_url": "https://example.com/app.js",
                    "source_location": None,
                    "extractor": "linkfinder",
                },
                {
                    "resolved_url": "https://example.com/api/login",
                    "raw_expression": "https://example.com/api/login",
                    "source_url": "https://example.com/vendor.js",
                    "source_location": None,
                    "extractor": "linkfinder",
                },
            ],
        }),
        encoding="utf-8",
    )

    findings = parse_linkfinder(raw)
    assert len(findings) == 1
    assert findings[0].occurrences == 2
    assert len(findings[0].metadata["provenance"]) == 2
    assert {item["source_url"] for item in findings[0].metadata["provenance"]} == {
        "https://example.com/app.js",
        "https://example.com/vendor.js",
    }


def test_linkfinder_reconciles_seed_origin_and_base_path_aliases(tmp_path):
    raw = tmp_path / "linkfinder.json"
    source_url = "https://secure.example.test/auth/main.js"
    raw.write_text(
        __import__("json").dumps({
            "schema_version": 3,
            "endpoints": [
                {
                    "resolved_url": "https://secure.example.test/v1/login",
                    "raw_expression": "/v1/login",
                    "source_url": source_url,
                    "extractor": "linkfinder",
                    "evidence_status": "discovered",
                    "confidence": "low",
                },
                {
                    "resolved_url": "https://api.example.test/public/v1/login",
                    "raw_expression": 'publicProxy + "/v1/login"',
                    "source_url": source_url,
                    "extractor": "deadbolt-js-static",
                    "evidence_status": "inferred",
                    "confidence": "medium",
                    "method": "POST",
                },
            ],
        }),
        encoding="utf-8",
    )

    findings = parse_linkfinder(raw)

    assert [finding.asset for finding in findings] == [
        "https://api.example.test/public/v1/login",
    ]
    assert findings[0].metadata["method"] == "POST"
    assert {
        item["raw_expression"] for item in findings[0].metadata["provenance"]
    } == {'/v1/login', 'publicProxy + "/v1/login"'}


def test_ffuf_preserves_scheme_port_and_base_path(monkeypatch, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("http://localhost:3000/shop/#/\n", encoding="utf-8")
    output = tmp_path / "raw" / "ffuf.json"
    output.parent.mkdir()
    captured = {}
    monkeypatch.setattr(
        ffuf_runner,
        "run_container",
        lambda **kwargs: captured.update(kwargs),
    )

    ffuf_runner.run_ffuf(targets, output)

    normalized = output.parent / "ffuf_targets.txt"
    assert normalized.read_text(encoding="utf-8") == "http://localhost:3000/shop"
    assert ["-u", "BASE/FUZZ"] == captured["args"][
        captured["args"].index("-u"):captured["args"].index("-u") + 2
    ]
    assert "-ac" in captured["args"]


def test_katana_uses_bounded_javascript_crawl_profile(monkeypatch, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://example.com\n", encoding="utf-8")
    output = tmp_path / "raw" / "katana.txt"
    output.parent.mkdir()
    captured = {}
    monkeypatch.setattr(
        katana_runner,
        "run_container",
        lambda **kwargs: captured.update(kwargs),
    )

    katana_runner.run_katana(targets, output)

    assert "-js-crawl" in captured["args"]
    assert "-jsluice" in captured["args"]
    assert "-kb-endpoints" in captured["args"]
    assert captured["args"][captured["args"].index("-depth") + 1] == "5"
    assert captured["args"][captured["args"].index("-field-scope") + 1] == "fqdn"


def test_katana_deep_spa_profile_enables_browser_xhr_and_jsonl(monkeypatch, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://example.com\n", encoding="utf-8")
    output = tmp_path / "raw" / "katana.txt"
    output.parent.mkdir()
    captured = {}
    def run(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            stdout=(
                '{"request":{"method":"GET","endpoint":"https://example.com/",'
                '"headers":{"Cookie":"secret","Authorization":"Bearer private"},'
                '"raw":"GET /"},"response":{"headers":{'
                '"Set-Cookie":"citrix_ns_id=secret-cookie; Secure",'
                '"api-supported-versions":"1.0","X-Secret":"private"},'
                '"body":"private-body"}}\n'
            )
        )

    monkeypatch.setattr(katana_runner, "run_container", run)

    katana_runner.run_katana(targets, output, profile=WebScanProfile.DEEP_SPA)

    for flag in (
        "-hybrid", "-system-chrome", "-no-sandbox", "-xhr-extraction",
        "-form-extraction", "-jsonl", "-omit-raw", "-omit-body",
    ):
        assert flag in captured["args"]
    assert captured["args"][captured["args"].index("-exclude-output-fields") + 1] == (
        "raw,body"
    )
    assert "-o" not in captured["args"]
    evidence = output.read_text(encoding="utf-8")
    assert "https://example.com/" in evidence
    assert "secret" not in evidence
    assert "private" not in evidence
    assert '"request_header_names":["Cookie","Authorization"]' in evidence
    assert '"response_header_names":["Set-Cookie","api-supported-versions","X-Secret"]' in evidence
    assert '"api_version_indicators":["api-supported-versions: 1.0"]' in evidence
    assert '"cookie_names":["citrix_ns_id"]' in evidence


def test_katana_safe_browser_capture_is_bounded_and_not_deep(monkeypatch, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://example.com\n", encoding="utf-8")
    output = tmp_path / "raw" / "katana.txt"
    output.parent.mkdir()
    captured = {}
    monkeypatch.setattr(
        katana_runner,
        "run_container",
        lambda **kwargs: (
            captured.update(kwargs)
            or SimpleNamespace(stdout='{"request":{"method":"GET","endpoint":"https://example.com/"}}\n')
        ),
    )

    katana_runner.run_katana(
        targets,
        output,
        profile=WebScanProfile.SAFE,
        browser_assisted=True,
        rate_limit=5,
    )

    args = captured["args"]
    assert args[args.index("-rate-limit") + 1] == "1"
    assert args[args.index("-depth") + 1] == "2"
    assert "-hybrid" in args
    assert "-xhr-extraction" in args
    assert "-jsonl" in args
    assert "-jsluice" not in args
    assert "-known-files" not in args
    assert "-automatic-form-fill" not in args
    assert "-o" not in args


def test_katana_deep_spa_retries_one_empty_hybrid_session(monkeypatch, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://example.com\n", encoding="utf-8")
    output = tmp_path / "raw" / "katana.txt"
    output.parent.mkdir()
    calls = []

    def run(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            stdout="" if len(calls) == 1 else '{"request":{"endpoint":"https://example.com/"}}\n',
            stderr="",
        )

    monkeypatch.setattr(katana_runner, "run_container", run)
    katana_runner.run_katana(targets, output, profile=WebScanProfile.DEEP_SPA)

    assert len(calls) == 2
    assert "https://example.com/" in output.read_text()
    assert "-headless-concurrency" not in calls[0]["args"]


def test_katana_parser_extracts_jsonl_xhr_methods(tmp_path):
    raw = tmp_path / "katana.txt"
    raw.write_text(
        '{"request":{"method":"GET","endpoint":"https://example.com/"},'
        '"xhr":[{"method":"POST","url":"/api/login"}]}\n',
        encoding="utf-8",
    )

    findings = parse_katana(raw)
    by_asset = {finding.asset: finding for finding in findings}

    assert "https://example.com/" in by_asset
    assert by_asset["https://example.com/api/login"].metadata["method"] == "POST"
    assert "xhr" in by_asset["https://example.com/api/login"].metadata["observation_types"]


def test_katana_parser_captures_value_free_request_body_schema_by_method(tmp_path):
    raw = tmp_path / "katana.jsonl"
    raw.write_text(
        '{"request":{"method":"GET","endpoint":"https://example.com/"},'
        '"xhr":[{"method":"POST","url":"/api/login",'
        '"body":"{\\"username\\":\\"private-user\\",\\"rememberMe\\":true,'
        '\\"attempts\\":3,\\"roles\\":[\\"admin\\"]}"}]}\n',
        encoding="utf-8",
    )

    finding = {
        item.asset: item for item in parse_katana(raw)
    }["https://example.com/api/login"]
    schema = finding.metadata["request_body_schema_by_method"]["POST"]

    assert schema == [
        {"name": "username", "data_type": "string", "required": None,
         "source": "browser-observed request body"},
        {"name": "rememberMe", "data_type": "boolean", "required": None,
         "source": "browser-observed request body"},
        {"name": "attempts", "data_type": "number", "required": None,
         "source": "browser-observed request body"},
        {"name": "roles", "data_type": "array", "required": None,
         "source": "browser-observed request body"},
    ]
    assert "private-user" not in repr(finding.metadata)

    inventory = runner._write_api_inventory(
        [finding], tmp_path, {"allow": ["example.com"], "deny": []}
    )
    assert inventory[0]["method"] == "POST"
    assert inventory[0]["request_body_fields"] == [
        {
            "name": item["name"],
            "location": "body",
            "data_type": item["data_type"],
            "source": item["source"],
        }
        for item in schema
    ]
    capture = (tmp_path / "enumeration.browser-requests.json").read_text(
        encoding="utf-8"
    )
    assert "private-user" not in capture


def test_browser_capture_pairs_preflight_with_application_request(tmp_path):
    raw = tmp_path / "katana.txt"
    raw.write_text(
        '{"request":{"method":"GET","endpoint":"https://example.com/"},'
        '"xhr":['
        '{"method":"OPTIONS","url":"/api/status"},'
        '{"method":"POST","url":"/api/status",'
        '"response":{"status_code":400,"content_type":"application/problem+json"}}'
        ']}' + "\n",
        encoding="utf-8",
    )
    findings = parse_katana(raw)
    inventory = runner._write_api_inventory(
        findings, tmp_path, {"allow": ["example.com"], "deny": []}
    )

    operations = [item for item in inventory if item["url"].endswith("/api/status")]
    assert len(operations) == 1
    assert operations[0]["method"] == "POST"
    assert operations[0]["preflight_observed"] is True
    assert operations[0]["evidence_status"] == "observed"
    assert operations[0]["confidence"] == "high"
    assert operations[0]["source"] == "katana-browser-xhr"
    assert operations[0]["status_code"] == 400
    assert operations[0]["response_content_type"] == "application/problem+json"

    capture = __import__("json").loads(
        (tmp_path / "enumeration.browser-requests.json").read_text()
    )
    assert [
        item["method"] for item in capture["requests"]
        if item["url"].endswith("/api/status")
    ] == ["POST"]
    assert [
        item["method"] for item in capture["preflights"]
        if item["url"].endswith("/api/status")
    ] == ["OPTIONS"]
    assert "body" not in capture["requests"][0]
    assert "headers" not in capture["requests"][0]


def test_api_inventory_separates_application_and_infrastructure_technology(tmp_path):
    endpoint = _finding("https://example.com/api/status", "katana", "path")
    endpoint.metadata = {
        "method": "POST",
        "status_code": 400,
        "content_type": "application/problem+json",
        "response_header_names": ["api-supported-versions", "Set-Cookie"],
        "api_version_indicators": ["api-supported-versions: 1.0"],
        "cookie_names": ["citrix_ns_id", "application_session"],
    }
    enrichment = _finding("https://example.com/api/status", "httpx", "path")
    enrichment.status_code = 400
    enrichment.technologies = ["ASP.NET", "nginx"]
    enrichment.webserver = "nginx"
    enrichment.cdn_name = "Cloudflare"
    enrichment.metadata = {"content_type": "application/problem+json"}

    inventory = runner._write_api_inventory(
        [endpoint, enrichment], tmp_path, {"allow": ["example.com"], "deny": []}
    )

    assert inventory[0]["application_technologies"] == ["ASP.NET"]
    assert inventory[0]["infrastructure_technologies"] == ["nginx", "Cloudflare"]
    assert inventory[0]["api_version_indicators"] == ["api-supported-versions: 1.0"]
    assert inventory[0]["infrastructure_cookie_names"] == ["citrix_ns_id"]
    assert "heuristic, not framework proof" in inventory[0]["framework_signals"][0]


def test_api_inventory_does_not_attach_get_probe_status_to_inferred_post(tmp_path):
    endpoint_url = "https://example.com/public/v1/login"
    inferred = _finding(endpoint_url, "linkfinder", "path")
    inferred.metadata = {
        "method": "POST",
        "methods": ["POST"],
        "evidence_status": "inferred",
        "confidence": "medium",
    }
    get_probe = _finding(endpoint_url, "httpx", "path")
    get_probe.status_code = 405
    get_probe.technologies = ["ASP.NET"]
    get_probe.metadata = {"content_type": "application/problem+json"}

    inventory = runner._write_api_inventory(
        [inferred, get_probe], tmp_path, {"allow": ["example.com"], "deny": []}
    )

    assert inventory[0]["method"] == "POST"
    assert "status_code" not in inventory[0]
    assert "response_content_type" not in inventory[0]
    assert inventory[0]["application_technologies"] == ["ASP.NET"]


def test_httpx_persists_classifier_cache(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    targets = tmp_path / "targets.txt"
    targets.write_text("https://example.com\n", encoding="utf-8")
    output = tmp_path / "raw" / "httpx.json"
    output.parent.mkdir()
    captured = {}
    monkeypatch.setattr(
        httpx_runner,
        "run_container",
        lambda **kwargs: captured.update(kwargs),
    )

    httpx_runner.run_httpx(targets, output)

    cache = tmp_path / ".deadbolt" / "cache" / "httpx" / "dit"
    assert cache.is_dir()
    assert captured["mounts"][cache] == "/root/.dit"


def test_route_quality_gate_separates_confirmed_spa_and_parser_noise(tmp_path):
    root = "https://example.com"
    canary = f"{root}/.deadbolt-not-found-test"

    def response(
        url, *, length=9393, content_type="text/html", status=200,
        title=None, location=None,
    ):
        item = _finding(url, "httpx_paths", "path")
        item.title = title or ("SPA shell" if length == 9393 else "Distinct response")
        item.status_code = status
        item.metadata = {
            "content_type": content_type, "content_length": length,
            "location": location,
        }
        return item

    random_uuid = f"{root}/271b24c3-c0b1-4b64-8dbe-f8ca0e028283"
    redirect_canary = f"{root}/.deadbolt-not-found-redirect"
    legitimate_uuid = (
        f"{root}/api/users/271b24c3-c0b1-4b64-8dbe-f8ca0e028283"
    )

    retained, confirmed = runner._route_quality_gate(
        findings=[
            response(canary),
            response(f"{root}/client-route"),
            response(f"{root}/metrics", length=1200, content_type="text/plain"),
            response(f"{root}/CallExpression/PropertyName"),
            response(f"{root}/auth/assets/application/vnd.ms-word.do", length=1200),
            response(
                redirect_canary, length=0, content_type="", status=302,
                title=f"Redirect detected: {redirect_canary} -> {root}/",
                location=f"{root}/",
            ),
            response(
                random_uuid, length=0, content_type="", status=302,
                title=f"Redirect detected: {random_uuid} -> {root}/",
                location=f"{root}/",
            ),
            response(legitimate_uuid, length=0, content_type="", status=401),
        ],
        canaries={canary, redirect_canary},
        roots={root},
        sources={
            f"{root}/client-route": {"katana"},
            f"{root}/metrics": {"ffuf"},
            f"{root}/CallExpression/PropertyName": {"linkfinder"},
            random_uuid: {"katana"},
            legitimate_uuid: {"katana"},
        },
        work_dir=tmp_path,
    )

    assert len(retained) == 6
    assert confirmed == [f"{root}/metrics", legitimate_uuid]
    assert (tmp_path / "enumeration.routes.candidates.txt").read_text() == (
        f"{root}/client-route\n{random_uuid}\n"
    )
    assert "parser or syntax artifact" in (
        tmp_path / "enumeration.routes.rejected.tsv"
    ).read_text()
    assert "application/vnd.ms-word.do" not in confirmed


def test_api_inventory_keeps_observed_method_separate_from_get_route_probe(tmp_path):
    endpoint = "https://example.com/rest/user/login"
    item = _finding(endpoint, "katana", "path")
    item.metadata = {"method": "POST"}
    (tmp_path / "enumeration.route-quality.json").write_text(
        __import__("json").dumps([{
            "url": endpoint,
            "disposition": "confirmed",
            "confidence": "high",
            "status_code": 401,
        }]),
        encoding="utf-8",
    )

    inventory = runner._write_api_inventory(
        [item], tmp_path, {"allow": ["example.com"], "deny": []}
    )

    assert len(inventory) == 1
    assert inventory[0]["method"] == "POST"
    assert inventory[0]["url"] == endpoint
    assert "status_code" not in inventory[0]
    assert inventory[0]["evidence_status"] == "observed"
    assert inventory[0]["confidence"] == "high"
    assert inventory[0]["scope_status"] == "in_scope"
    assert inventory[0]["route_disposition"] == "observed"
    assert inventory[0]["route_confidence"] == "high"
    assert inventory[0]["source"] == "katana-browser"
    artifact = __import__("json").loads(
        (tmp_path / "enumeration.api-inventory.json").read_text()
    )
    assert artifact["schema_version"] == 1
    assert artifact["entries"] == inventory


def test_api_inventory_does_not_reintroduce_static_browser_noise(tmp_path):
    fake = _finding(
        "https://example.com/auth/assets/application/vnd.ms-word.do",
        "katana",
        "path",
    )
    fake.metadata = {"method": "GET", "observation_type": "xhr"}
    static_file = _finding(
        "https://example.com/auth/assets/app.js",
        "katana",
        "path",
    )
    static_file.metadata = {"method": "GET", "observation_type": "xhr"}

    inventory = runner._write_api_inventory(
        [fake, static_file], tmp_path, {"allow": ["example.com"], "deny": []}
    )

    assert inventory == []


def test_api_inventory_redacts_and_collapses_socket_transport(tmp_path):
    first = _finding(
        "https://example.com/socket.io/?EIO=4&transport=polling&t=one&sid=secret-one",
        "katana", "path",
    )
    second = _finding(
        "https://example.com/socket.io/?transport=polling&EIO=4&t=two&sid=secret-two",
        "katana", "path",
    )
    first.metadata = second.metadata = {"method": "POST"}

    inventory = runner._write_api_inventory([first, second], tmp_path)

    assert len(inventory) == 1
    assert inventory[0]["url"] == "https://example.com/socket.io/"
    assert inventory[0]["surface_type"] == "realtime transport"
    assert [item["name"] for item in inventory[0]["query_parameters"]] == [
        "EIO", "transport"
    ]
    assert "secret" not in (tmp_path / "enumeration.api-inventory.json").read_text()


def test_api_inventory_extracts_value_free_query_and_dynamic_path_schema(tmp_path):
    observed = _finding(
        "https://example.com/api/users/550e8400-e29b-41d4-a716-446655440000"
        "?active=true&limit=10&ratio=1.5&empty=",
        "katana",
        "path",
    )
    observed.metadata = {"method": "GET", "observation_type": "xhr"}
    inferred = _finding(
        "https://example.com/api/accounts/{accountId}",
        "linkfinder",
        "path",
    )
    inferred.metadata = {
        "method": "GET",
        "methods": ["GET"],
        "evidence_status": "inferred",
        "confidence": "medium",
    }

    inventory = runner._write_api_inventory(
        [observed, inferred], tmp_path, {"allow": ["example.com"], "deny": []}
    )
    by_url = {item["url"]: item for item in inventory}

    observed_schema = by_url[
        "https://example.com/api/users/550e8400-e29b-41d4-a716-446655440000"
    ]
    assert {
        item["name"]: item.get("data_type")
        for item in observed_schema["query_parameters"]
    } == {
        "active": "boolean", "limit": "integer", "ratio": "number", "empty": None,
    }
    assert observed_schema["path_parameters"] == [{
        "name": "path_segment_3",
        "location": "path",
        "data_type": "uuid",
        "required": True,
        "source": "browser-observed URL",
    }]
    assert by_url[
        "https://example.com/api/accounts/{accountId}"
    ]["path_parameters"] == [{
        "name": "accountId",
        "location": "path",
        "required": True,
        "source": "JavaScript-discovered URL",
    }]
    artifact = (tmp_path / "enumeration.api-inventory.json").read_text(encoding="utf-8")
    assert "550e8400" in artifact  # endpoint evidence remains auditable
    assert "?active=true" not in artifact  # query values are never persisted
    capture = json.loads(
        (tmp_path / "enumeration.browser-requests.json").read_text(encoding="utf-8")
    )
    assert {
        item["name"]: item.get("data_type")
        for item in capture["requests"][0]["query_parameters"]
    }["limit"] == "integer"
    assert "active=true" not in json.dumps(capture)


def test_api_inventory_preserves_javascript_context_and_unknown_scope(tmp_path):
    item = _finding("https://api.other.test/v1/login?locale=en", "linkfinder", "path")
    item.evidence_path = str(tmp_path / "linkfinder.json")
    item.metadata = {
        "raw_expression": 'publicProxy + "/v1/login"',
        "source_url": "https://example.com/assets/app.js",
        "source_location": None,
        "extractor": "linkfinder",
        "provenance": [{
            "raw_expression": 'publicProxy + "/v1/login"',
            "source_url": "https://example.com/assets/app.js",
            "source_location": None,
            "extractor": "linkfinder",
        }],
    }
    inventory = runner._write_api_inventory(
        [item], tmp_path, {"allow": ["example.com"], "deny": []}
    )
    assert len(inventory) == 1
    assert "method" not in inventory[0]
    assert inventory[0]["url"] == "https://api.other.test/v1/login"
    assert inventory[0]["evidence_status"] == "discovered"
    assert inventory[0]["confidence"] == "low"
    assert inventory[0]["scope_status"] == "unknown"
    assert inventory[0]["raw_expression"] == 'publicProxy + "/v1/login"'
    assert inventory[0]["provenance"][0]["source_url"] == "https://example.com/assets/app.js"
    assert "source_location" not in inventory[0]["provenance"][0]
    assert [parameter["name"] for parameter in inventory[0]["query_parameters"]] == ["locale"]


def test_api_inventory_merges_javascript_provenance_into_observed_operation(tmp_path):
    endpoint = "https://example.com/api/login"
    browser = _finding(endpoint, "katana", "path")
    browser.metadata = {
        "method": "POST", "request_header_names": ["Content-Type"],
    }
    javascript = _finding(endpoint, "linkfinder", "path")
    javascript.metadata = {
        "method": "POST",
        "methods": ["POST"],
        "evidence_status": "inferred",
        "confidence": "medium",
        "request_body_fields_by_method": {"POST": ["username", "password"]},
        "request_header_names": ["X-Requested-With"],
        "credentials_mode": "include",
        "wrapper_chain": ["requestJson"],
        "raw_expression": 'baseURL + "/api/login"',
        "provenance": [{
            "raw_expression": 'baseURL + "/api/login"',
            "source_url": "https://example.com/app.js",
            "source_location": None,
            "extractor": "linkfinder",
        }],
    }
    inventory = runner._write_api_inventory(
        [browser, javascript], tmp_path, {"allow": ["example.com"], "deny": []}
    )
    assert len(inventory) == 1
    assert inventory[0]["method"] == "POST"
    assert inventory[0]["evidence_status"] == "observed"
    assert inventory[0]["confidence"] == "high"
    assert inventory[0]["raw_expression"] == 'baseURL + "/api/login"'
    assert [field["name"] for field in inventory[0]["request_body_fields"]] == [
        "username", "password",
    ]
    assert inventory[0]["request_header_names"] == [
        "Content-Type", "X-Requested-With",
    ]
    assert inventory[0]["credentials_mode"] == "include"
    assert inventory[0]["wrapper_chain"] == ["requestJson"]
    assert {item["source"] for item in inventory[0]["provenance"]} == {
        "katana-browser", "linkfinder",
    }


def test_api_inventory_preserves_observed_schema_and_reports_static_conflicts(tmp_path):
    endpoint = "https://example.com/api/login"
    browser = _finding(endpoint, "katana", "path")
    browser.metadata = {
        "method": "POST",
        "request_body_schema_by_method": {
            "POST": [{
                "name": "username", "data_type": "string", "required": None,
                "source": "browser-observed request body",
            }],
        },
    }
    javascript = _finding(endpoint, "linkfinder", "path")
    javascript.metadata = {
        "method": "POST",
        "methods": ["POST"],
        "evidence_status": "inferred",
        "confidence": "medium",
        "request_body_fields_by_method": {"POST": ["username"]},
        "request_body_schema": [{
            "name": "username", "data_type": "number", "required": True,
            "source": "JavaScript request object",
        }],
    }

    inventory = runner._write_api_inventory(
        [browser, javascript], tmp_path, {"allow": ["example.com"], "deny": []}
    )

    assert inventory[0]["request_body_fields"] == [{
        "name": "username",
        "location": "body",
        "data_type": "string",
        "required": True,
        "source": "browser-observed request body",
    }]
    assert inventory[0]["request_schema_conflicts"] == [{
        "field_name": "username",
        "location": "body",
        "attribute": "data_type",
        "observed": "string",
        "inferred": "number",
    }]


def test_api_inventory_merge_is_independent_of_evidence_order(tmp_path):
    endpoint = "https://example.com/api/login"
    javascript = _finding(endpoint, "linkfinder", "path")
    javascript.metadata = {
        "method": "POST", "methods": ["POST"],
        "evidence_status": "inferred", "confidence": "medium",
        "request_body_fields": ["username"],
        "request_body_fields_by_method": {"POST": ["username"]},
        "request_header_names": ["X-Client"],
        "raw_expression": 'apiBase + "/login"',
    }
    browser = _finding(endpoint, "katana", "path")
    browser.metadata = {
        "method": "POST", "request_header_names": ["Content-Type"],
    }

    inventory = runner._write_api_inventory(
        [javascript, browser], tmp_path, {"allow": ["example.com"], "deny": []}
    )

    assert len(inventory) == 1
    assert inventory[0]["evidence_status"] == "observed"
    assert inventory[0]["raw_expression"] == 'apiBase + "/login"'
    assert [field["name"] for field in inventory[0]["request_body_fields"]] == [
        "username",
    ]
    assert inventory[0]["request_header_names"] == ["Content-Type", "X-Client"]


def test_api_inventory_promotes_unknown_method_context_when_browser_observes_method(
    tmp_path,
):
    endpoint = "https://example.com/api/callback"
    javascript = _finding(endpoint, "linkfinder", "path")
    javascript.metadata = {
        "evidence_status": "inferred", "confidence": "medium",
        "request_body_fields": ["state", "code"],
        "request_header_names": ["X-Client"],
        "credentials_mode": "include",
        "wrapper_chain": ["requestJson"],
        "raw_expression": 'apiBase + "/callback"',
    }
    browser = _finding(endpoint, "katana", "path")
    browser.metadata = {"method": "POST"}

    inventory = runner._write_api_inventory(
        [javascript, browser], tmp_path, {"allow": ["example.com"], "deny": []}
    )

    assert len(inventory) == 1
    assert inventory[0]["method"] == "POST"
    assert inventory[0]["evidence_status"] == "observed"
    assert [field["name"] for field in inventory[0]["request_body_fields"]] == [
        "state", "code",
    ]
    assert inventory[0]["request_header_names"] == ["X-Client"]
    assert inventory[0]["credentials_mode"] == "include"
    assert inventory[0]["wrapper_chain"] == ["requestJson"]


def test_inferred_only_javascript_urls_do_not_enter_active_worklists():
    inferred = _finding("https://example.com/api/inferred", "linkfinder", "path")
    inferred.metadata = {
        "evidence_status": "inferred",
        "provenance": [{"evidence_status": "inferred"}],
    }
    corroborated = _finding("https://example.com/api/corroborated", "linkfinder", "path")
    corroborated.metadata = {
        "evidence_status": "inferred",
        "provenance": [
            {"evidence_status": "discovered"},
            {"evidence_status": "inferred"},
        ],
    }

    assert runner._active_linkfinder_findings([inferred, corroborated]) == [corroborated]


def test_local_lab_preserves_port_skips_public_recon_and_scans_transport(
    monkeypatch, tmp_path
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "scope.yaml").write_text("allow:\n  - example.com\ndeny: []\n")
    targets = tmp_path / "juice-shop.txt"
    targets.write_text("http://localhost:3000/#/\n", encoding="utf-8")
    run_dir = tmp_path / "outputs" / "run_local"
    monkeypatch.setattr(runner, "_resolve_run_base", lambda resume: run_dir)
    monkeypatch.setattr(runner, "ExecutionTable", FakeExecutionTable)
    monkeypatch.setattr(runner, "get_fresh_cached_versions", lambda image: ("test", "test"))
    metadata = []
    monkeypatch.setattr(runner, "write_metadata", lambda **kwargs: metadata.append(kwargs))
    monkeypatch.setattr(runner, "generate_report", lambda path: None)
    monkeypatch.setattr(runner, "preflight_local_lab_targets", lambda targets: None)
    calls = []
    nuclei_inputs = []

    def fake_run_tool(*, spec, table, input_file, base_dir, scan_profile):
        values = input_file.read_text().splitlines()
        calls.append((spec.name, values))
        if spec.name == "httpx":
            return [_finding("http://host.docker.internal:3000/", spec.name, "asset")]
        if spec.name == "katana":
            return [_finding("http://host.docker.internal:3000/assets/app.js", spec.name, "path")]
        if spec.name == "httpx_paths":
            return [_finding(value, spec.name, "path") for value in values]
        if spec.name == "nuclei":
            nuclei_inputs.extend(values)
            return []
        return []

    monkeypatch.setattr(runner, "run_tool", fake_run_tool)
    runner.run_web(str(targets), local_lab=True)

    names = [name for name, _ in calls]
    assert "subfinder" not in names
    assert "dnsx" not in names
    assert "gau" not in names
    assert "waybackurls" not in names
    assert "paramspider" not in names
    assert ("httpx", ["http://host.docker.internal:3000/"]) in calls
    assert "http://host.docker.internal:3000/" in nuclei_inputs
    assert "http://host.docker.internal:3000/assets/app.js" not in nuclei_inputs
    assert (run_dir / "work" / "enumeration.application-routes.in_scope.txt").read_text() == ""
    assert (run_dir / "work" / "input.targets.txt").read_text() == "http://localhost:3000/\n"
    assert (run_dir / "work" / "targets.transport.txt").read_text() == (
        "http://host.docker.internal:3000/\n"
    )
    state = __import__("json").loads((run_dir / "state.json").read_text())
    assert state["tools"]["subfinder"]["status"] == "not_applicable"
    snapshot = (run_dir / state["scope"]["snapshot"]).read_text()
    assert "host.docker.internal" in snapshot
    assert metadata[0]["local_lab"] is True
    assert metadata[0]["scan_profile"] == "standard"
    assert metadata[0]["target_mapping"] == {
        "http://host.docker.internal:3000/": "http://localhost:3000/"
    }

    # Current runs use immutable stage artifacts such as
    # discovery.httpx.live.txt and per-tool enumeration worklists. Resuming
    # must not require obsolete discovery.assets.txt/enumeration.paths.txt.
    calls.clear()
    runner.run_web(
        str(run_dir / "work" / "input.targets.txt"),
        resume_from=run_dir,
        local_lab=True,
    )


def test_run_tool_publishes_staged_output_and_removes_stale_sidecars(monkeypatch, tmp_path):
    base = tmp_path / "run"
    raw_dir = base / "raw" / "atomic-test"
    raw_dir.mkdir(parents=True)
    (raw_dir / "result.txt").write_text("stale\n", encoding="utf-8")
    (raw_dir / "obsolete.txt").write_text("obsolete\n", encoding="utf-8")
    input_file = tmp_path / "input.txt"
    input_file.write_text("example.com\n", encoding="utf-8")

    def execute(_input, output):
        output.write_text("fresh\n", encoding="utf-8")
        (output.parent / "sidecar.txt").write_text("evidence\n", encoding="utf-8")

    def parse(output):
        assert ".deadbolt-stage-" in str(output)
        return [_finding("fresh", "atomic-test", "asset")]

    monkeypatch.setitem(
        runner.TOOL_RUNTIMES,
        "atomic-test",
        ToolRuntime(runner=execute, parser=parse, output_name="result.txt"),
    )
    findings = runner.run_tool(
        spec=SimpleNamespace(name="atomic-test"),
        table=FakeExecutionTable(),
        input_file=input_file,
        base_dir=base,
    )

    assert (raw_dir / "result.txt").read_text() == "fresh\n"
    assert (raw_dir / "sidecar.txt").read_text() == "evidence\n"
    assert not (raw_dir / "obsolete.txt").exists()
    assert findings[0].evidence_path == str(raw_dir / "result.txt")
    assert not list(raw_dir.glob(".deadbolt-stage-*"))


def test_run_tool_failure_preserves_previous_valid_evidence(monkeypatch, tmp_path):
    base = tmp_path / "run"
    raw_dir = base / "raw" / "atomic-test"
    raw_dir.mkdir(parents=True)
    durable = raw_dir / "result.txt"
    durable.write_text("last-valid\n", encoding="utf-8")
    input_file = tmp_path / "input.txt"
    input_file.write_text("example.com\n", encoding="utf-8")

    def fail(_input, output):
        output.write_text("partial\n", encoding="utf-8")
        raise RuntimeError("interrupted")

    monkeypatch.setitem(
        runner.TOOL_RUNTIMES,
        "atomic-test",
        ToolRuntime(runner=fail, parser=lambda output: [], output_name="result.txt"),
    )

    try:
        runner.run_tool(
            spec=SimpleNamespace(name="atomic-test"),
            table=FakeExecutionTable(),
            input_file=input_file,
            base_dir=base,
        )
    except RuntimeError as exc:
        assert str(exc) == "interrupted"
    else:
        raise AssertionError("expected staged execution failure")

    assert durable.read_text() == "last-valid\n"
    assert not list(raw_dir.glob(".deadbolt-stage-*"))
