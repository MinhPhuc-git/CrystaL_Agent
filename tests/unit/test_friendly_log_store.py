import json

from crystal.rawstore.friendly import FriendlyLogStore


def test_events_are_single_line_ecs_logs_grouped_by_windows_event_id(tmp_path):
    store = FriendlyLogStore(tmp_path)
    record = {
        "event_uid": "Security:42:4624", "event_id": 4624,
        "event_name": "Logon success", "time_created": "2026-11-02T10:00:00Z",
        "computer": "pc", "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "42", "event_data": {
            "TargetUserName": "alice", "TargetDomainName": "WORKGROUP",
            "LogonType": "3", "IpAddress": "10.0.0.2",
            "ProcessName": r"C:\\Windows\\System32\\services.exe", "ProcessId": "0x6ac",
        },
    }
    normalized = {
        "event_uid": "Security:42:4624", "event_type": "auth.success",
        "event_id": 4624, "event_time": "2026-11-02T10:00:00+00:00",
        "target_host": "pc", "account": "alice", "source_ip": "10.0.0.2",
        "logon_type": "3", "source": "Security",
    }

    success_path = store.append(record, normalized)
    failure_path = store.append({**record, "event_id": 4625, "event_uid": "Security:43:4625"})
    store.append({**record, "event_uid": "Security:44:4624"}, normalized)

    assert success_path.name == "event-4624.log"
    assert failure_path.name == "event-4625.log"
    text = success_path.read_text(encoding="utf-8")
    assert all(line.startswith("{") and line.endswith("}") for line in text.splitlines())
    rows = [json.loads(line) for line in text.splitlines()]
    assert len(rows) == 2
    event = rows[0]
    assert event["ecs"]["version"] == "9.5.0"
    assert event["@timestamp"] == "2026-11-02T17:00:00+07:00"
    assert event["event"]["code"] == "4624"
    assert event["event"]["category"] == ["authentication"]
    assert event["event"]["outcome"] == "success"
    assert event["user"]["name"] == "alice"
    assert event["source"]["ip"] == "10.0.0.2"
    assert event["process"]["pid"] == 1708
    assert event["authentication"]["type"] == "3"
    assert "event_data" not in event["winlog"]
