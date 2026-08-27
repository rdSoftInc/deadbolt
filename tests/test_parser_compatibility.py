import json
from pathlib import Path

from main.tools.androguard.parser import parse_androguard
from main.tools.apktool.parser import parse_apktool
from main.tools.httpx.parser import parse_httpx
from main.tools.nuclei.parser import parse_nuclei


FIXTURES = Path(__file__).parent / "fixtures"
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _manifest(target_sdk: int) -> str:
    return f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.test">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="{target_sdk}" />
  <application android:debuggable="false" android:allowBackup="false">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
      </intent-filter>
    </activity>
  </application>
</manifest>'''


def _outdated_sdk_finding(findings):
    return next(f for f in findings if f.title.startswith("Target SDK version outdated"))


def test_httpx_v1_9_jsonl_is_parsed_and_deduplicated():
    findings = parse_httpx(FIXTURES / "httpx-v1.9.jsonl")

    assert len(findings) == 1
    assert findings[0].asset == "https://example.com/"
    assert findings[0].status_code == 403
    assert findings[0].occurrences == 2


def test_nuclei_v3_8_jsonl_keeps_highest_severity():
    findings = parse_nuclei(FIXTURES / "nuclei-v3.8.jsonl")

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].occurrences == 2
    assert findings[0].metadata["owasp"] == ["A03:2021 Injection"]


def test_apktool_flags_api_35_against_api_36_policy(tmp_path):
    raw = tmp_path / "apktool.json"
    (tmp_path / "AndroidManifest.xml").write_text(_manifest(35), encoding="utf-8")
    raw.write_text(json.dumps({"manifest": "AndroidManifest.xml"}), encoding="utf-8")

    finding = _outdated_sdk_finding(parse_apktool(raw))
    assert finding.metadata["recommended_target_sdk"] == 36


def test_androguard_flags_api_35_against_api_36_policy(tmp_path):
    raw = tmp_path / "androguard.json"
    raw.write_text(
        json.dumps({"axml": _manifest(35), "sign": "Is signed v2: True"}),
        encoding="utf-8",
    )

    finding = _outdated_sdk_finding(parse_androguard(raw))
    assert finding.metadata["recommended_target_sdk"] == 36


def test_android_api_36_is_not_reported_as_outdated(tmp_path):
    raw = tmp_path / "apktool.json"
    (tmp_path / "AndroidManifest.xml").write_text(_manifest(36), encoding="utf-8")
    raw.write_text(json.dumps({"manifest": "AndroidManifest.xml"}), encoding="utf-8")

    assert not any(
        finding.title.startswith("Target SDK version outdated")
        for finding in parse_apktool(raw)
    )
