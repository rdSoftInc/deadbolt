from main.core.execution_table import ExecutionTable, format_duration


def test_duration_format_switches_to_minutes_and_hours():
    assert format_duration(0) == "0.0s"
    assert format_duration(33.84) == "33.8s"
    assert format_duration(59.94) == "59.9s"
    assert format_duration(60) == "1m 0s"
    assert format_duration(80.9) == "1m 20s"
    assert format_duration(947.9) == "15m 47s"
    assert format_duration(3723.9) == "1h 2m 3s"


def test_execution_table_distinguishes_cached_results_from_empty_input(monkeypatch):
    table = ExecutionTable()
    monkeypatch.setattr(table, "_refresh", lambda: None)
    table.register_tool("resumed", "1.0")
    table.register_tool("empty", "1.0")

    table.tool_cached("resumed", findings=8, duration_seconds=12.34)
    table.tool_no_input("empty")
    table.tool_result_summary("resumed", "8")

    assert table.status["resumed"] == "cached"
    assert table.status["empty"] == "no_input"
    assert table.result_summaries["resumed"] == "8"
    assert table.findings["resumed"] == 8
    assert table.durations["resumed"] == 12.34
    rendered = str(table._render())
    assert rendered


def test_execution_table_uses_non_blocking_pinned_update_state():
    table = ExecutionTable()
    table.register_tool("scanner", "1.2.3")

    assert table.update_status["scanner"] == "pinned"
