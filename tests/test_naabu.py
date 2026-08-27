import json

from main.tools.naabu.parser import parse_naabu


def test_naabu_parser_preserves_ports_and_service_metadata(tmp_path):
    raw = tmp_path / "naabu.jsonl"
    raw.write_text(json.dumps({"host": "api.example.com", "ip": "192.0.2.4", "port": 8443, "protocol": "tcp", "service": "https"}) + "\n")
    findings = parse_naabu(raw)
    assert [item.asset for item in findings] == ["api.example.com:8443"]
    assert findings[0].metadata["service"] == "https"
