import json
from pathlib import Path

from main.tools.arjun.parser import parse_arjun
from main.tools.arjun.runner import run_arjun


def test_arjun_parser_builds_parameterized_url(tmp_path):
    raw=tmp_path/'arjun.json'; raw.write_text(json.dumps({'https://example.com/search':['q','page']}))
    result=parse_arjun(raw)
    assert result[0].asset == 'https://example.com/search?page=&q='
    assert result[0].metadata['active_probe'] is True


def test_arjun_runner_publishes_empty_json_when_no_parameters_found(tmp_path, monkeypatch):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://example.com/\n", encoding="utf-8")
    output = tmp_path / "raw" / "arjun.json"
    output.parent.mkdir()

    monkeypatch.setattr("main.tools.arjun.runner.run_container", lambda **kwargs: None)

    run_arjun(targets, output)

    assert json.loads(output.read_text(encoding="utf-8")) == {}


def test_arjun_runner_preserves_generated_output(tmp_path, monkeypatch):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://example.com/search\n", encoding="utf-8")
    output = tmp_path / "raw" / "arjun.json"
    output.parent.mkdir()

    def fake_container(*, mounts: dict[Path, str], **kwargs):
        host_output = next(path for path, destination in mounts.items() if destination == "/output")
        (host_output / "arjun.json").write_text(
            json.dumps({"https://example.com/search": ["q"]}), encoding="utf-8"
        )

    monkeypatch.setattr("main.tools.arjun.runner.run_container", fake_container)

    run_arjun(targets, output)

    assert json.loads(output.read_text(encoding="utf-8")) == {
        "https://example.com/search": ["q"]
    }
