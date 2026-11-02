from crystal.collectors.windows.auth.security_events import _to_record


def test_event_is_friendly_compact_and_contains_no_xml():
    row = _to_record({"record_id":"42", "event_id":4625,
                      "time_created":"2026-11-02T00:00:00Z", "computer":"LAB-PC",
                      "provider":"Microsoft-Windows-Security-Auditing",
                      "event_data":{"TargetUserName":"alice", "IpAddress":"192.0.2.4"}})
    assert row["agent"] == "CrystaL"
    assert row["platform"] == "Windows"
    assert row["event_name"] == "Đăng nhập thất bại"
    assert "alice" in row["friendly_view"]
    assert "xml" not in row
