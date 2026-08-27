import json
from main.tools.tlsx.parser import parse_tlsx


def test_tlsx_parser(tmp_path):
    raw=tmp_path/'tlsx.jsonl'; raw.write_text(json.dumps({'host':'example.com:443','tls_version':'tls13'})+'\n')
    result=parse_tlsx(raw)
    assert result[0].asset == 'example.com:443'
    assert result[0].metadata['tls_version'] == 'tls13'
