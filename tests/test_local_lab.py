import pytest
from types import SimpleNamespace

from main.utils import local_lab
from main.utils.local_lab import normalize_local_lab_target, normalize_local_lab_targets
from main.report.generator import _display_target


def test_local_lab_preserves_port_path_query_and_drops_fragment():
    target = normalize_local_lab_target("http://localhost:3000/#/")

    assert target.canonical == "http://localhost:3000/"
    assert target.transport == "http://host.docker.internal:3000/"
    assert target.original == "http://localhost:3000/#/"


def test_local_lab_accepts_loopback_and_deduplicates_canonical_urls():
    targets = normalize_local_lab_targets([
        "http://127.0.0.1:8080/api?x=1#client",
        "http://127.0.0.1:8080/api?x=1#other",
    ])

    assert len(targets) == 1
    assert targets[0].transport == "http://host.docker.internal:8080/api?x=1"


@pytest.mark.parametrize("value", ["localhost:3000", "http://example.com", "ftp://localhost"])
def test_local_lab_rejects_non_http_or_non_loopback_targets(value):
    with pytest.raises(ValueError):
        normalize_local_lab_target(value)


def test_report_mapping_keeps_docker_transport_internal():
    mapping = {"http://host.docker.internal:3000/": "http://localhost:3000/"}

    assert _display_target("http://host.docker.internal:3000/assets/app.js", mapping) == (
        "http://localhost:3000/assets/app.js"
    )


def test_local_lab_preflight_checks_host_and_docker(monkeypatch):
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    host_checks = []
    docker_commands = []
    monkeypatch.setattr(
        local_lab.socket,
        "create_connection",
        lambda address, timeout: host_checks.append((address, timeout)) or Connection(),
    )

    def run(command, **kwargs):
        docker_commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    target = normalize_local_lab_target("http://localhost:3000/")
    local_lab.preflight_local_lab_targets([target], command_runner=run)

    assert host_checks == [(('localhost', 3000), 5.0)]
    assert "host.docker.internal" in docker_commands[0]
    assert "3000" in docker_commands[0]


def test_local_lab_preflight_stops_before_docker_when_host_is_down(monkeypatch):
    monkeypatch.setattr(
        local_lab.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("connection refused")),
    )
    target = normalize_local_lab_target("http://localhost:3000/")

    with pytest.raises(local_lab.LocalLabPreflightError, match="publishes its port"):
        local_lab.preflight_local_lab_targets(
            [target],
            command_runner=lambda *args, **kwargs: pytest.fail("Docker should not run"),
        )
