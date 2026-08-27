from main.tools.nuclei import runner
from main.domains.web.profiles import WebScanProfile


def test_nuclei_mounts_secret_config_without_putting_token_in_args(monkeypatch, tmp_path):
    targets=tmp_path/'targets'; targets.write_text('https://example.com\n')
    output=tmp_path/'out'/'nuclei.jsonl'; output.parent.mkdir()
    monkeypatch.setattr(runner, 'environment_for_provider', lambda name: {'INTERACTSH_SERVER':'oast.example','INTERACTSH_TOKEN':'secret'})
    captured={}
    monkeypatch.setattr(runner, 'run_container', lambda **kwargs: captured.update(kwargs))
    runner.run_nuclei(targets, output)
    assert 'secret' not in ' '.join(captured['args'])
    assert '/deadbolt-config.yaml' in captured['mounts'].values()
    assert captured['args'][captured['args'].index('-severity') + 1] == 'medium,high,critical'


def test_safe_nuclei_is_bounded_and_technology_aware(monkeypatch, tmp_path):
    targets = tmp_path / 'targets'
    targets.write_text('https://example.com\n')
    output = tmp_path / 'out' / 'nuclei.jsonl'
    output.parent.mkdir()
    calls = []

    monkeypatch.setattr(
        runner,
        'environment_for_provider',
        lambda name: {'INTERACTSH_TOKEN': 'must-not-be-mounted'},
    )
    monkeypatch.setattr(
        runner,
        'run_container',
        lambda **kwargs: calls.append(kwargs),
    )

    runner.run_nuclei(targets, output, profile=WebScanProfile.SAFE)

    assert len(calls) == 2
    baseline, automatic = (call['args'] for call in calls)
    assert baseline[baseline.index('-t') + 1] == 'http/exposures'
    assert baseline[baseline.index('-severity') + 1] == 'high,critical'
    assert baseline[baseline.index('-max-time') + 1] == '3m'
    assert '-automatic-scan' in automatic
    assert automatic[automatic.index('-severity') + 1] == 'medium,high,critical'
    assert automatic[automatic.index('-max-time') + 1] == '12m'
    assert '-no-interactsh' in baseline and '-no-interactsh' in automatic
    assert all('/deadbolt-config.yaml' not in call['mounts'].values() for call in calls)
    assert output.read_text() == ''


def test_nuclei_severity_threshold_includes_more_severe_levels():
    assert runner._severities_at_least('low') == 'low,medium,high,critical'
    assert runner._severities_at_least('high') == 'high,critical'
    assert runner._severities_at_least('critical') == 'critical'


def test_bounded_nuclei_accepts_its_graceful_max_time_shutdown(monkeypatch):
    def max_time_shutdown(**kwargs):
        raise RuntimeError(
            'Docker failed\n'
            'CTRL+C pressed: Exiting\n'
            'Attempting graceful shutdown...\n'
            'Creating resume file: /root/.cache/nuclei/resume.cfg'
        )

    monkeypatch.setattr(runner, 'run_container', max_time_shutdown)
    runner._run_bounded_nuclei(image='nuclei', args=[], mounts={})


def test_bounded_nuclei_rejects_real_container_failures(monkeypatch):
    def real_failure(**kwargs):
        raise RuntimeError('Docker failed\ninvalid template')

    monkeypatch.setattr(runner, 'run_container', real_failure)
    try:
        runner._run_bounded_nuclei(image='nuclei', args=[], mounts={})
    except RuntimeError as exc:
        assert 'invalid template' in str(exc)
    else:
        raise AssertionError('real Nuclei failure was incorrectly accepted')
