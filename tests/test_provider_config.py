from main.core.provider_config import environment_for_provider, provider_statuses


def test_provider_config_never_requires_or_exposes_values(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SHODAN_API_KEY=super-secret\nCENSYS_PAT=\n", encoding="utf-8")
    statuses = {item.name: item for item in provider_statuses(env_file)}

    assert statuses["shodan"].configured is True
    assert statuses["shodan"].configured_variables == ("SHODAN_API_KEY",)
    assert "super-secret" not in repr(statuses["shodan"])
    assert statuses["censys"].configured is False
    assert environment_for_provider("shodan", env_file) == {
        "SHODAN_API_KEY": "super-secret"
    }


def test_process_environment_overrides_dotenv(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SHODAN_API_KEY=file-value\n", encoding="utf-8")
    monkeypatch.setenv("SHODAN_API_KEY", "process-value")
    assert environment_for_provider("shodan", env_file)["SHODAN_API_KEY"] == "process-value"
