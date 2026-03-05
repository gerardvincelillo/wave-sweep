import json

import wavesweep


def test_security_posture_and_vulnerability_detection() -> None:
    auditor = wavesweep.WaveSweep()
    auditor.aps = {
        "aa:bb": {"SSID": "linksys-home", "BSSID": "aa:bb", "Capabilities": "", "RSSI": -50, "Type": "AP"},
        "cc:dd": {"SSID": "OfficeWiFi", "BSSID": "cc:dd", "Capabilities": "privacy", "RSSI": -45, "Type": "AP"},
    }
    vulnerabilities = auditor.detect_vulnerabilities()
    assert "aa:bb" in vulnerabilities
    posture = auditor._security_posture()
    assert posture["score"] < 100


def test_generate_json_report(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(wavesweep, "REPORT_DIR", str(tmp_path))
    auditor = wavesweep.WaveSweep()
    auditor.aps = {
        "aa:bb": {"SSID": "TestAP", "BSSID": "aa:bb", "Capabilities": "privacy", "RSSI": -40, "Type": "AP"}
    }
    auditor.detect_vulnerabilities()
    auditor.detect_rogues()
    auditor.generate_report("json")
    created = list(tmp_path.glob("*.json"))
    assert len(created) == 1
    payload = json.loads(created[0].read_text(encoding="utf-8"))
    assert "security_posture" in payload
