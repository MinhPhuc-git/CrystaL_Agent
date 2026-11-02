from crystal.normalization.auth import normalize_auth


def test_auth_event_fields_are_normalized():
    e = normalize_auth({"event_id":4625,"record_id":"10","time_created":"2026-11-02T10:00:00Z",
                        "computer":"LAB-PC","channel":"Security",
                        "event_data":{"TargetUserName":"alice","IpAddress":"192.0.2.2","LogonType":"3"}})
    assert e is not None
    assert e.event_uid == "10"
    assert e.account == "alice"
    assert e.source_ip == "192.0.2.2"


def test_unrelated_event_is_ignored():
    assert normalize_auth({"event_id":5152}) is None
