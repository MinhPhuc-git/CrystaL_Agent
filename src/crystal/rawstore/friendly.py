from pathlib import Path
import json
from typing import Any
from crystal.timeutil import now_vietnam, iso_vietnam


def _first(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def _as_pid(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        # Windows có thể ghi PID và port ở dạng thập phân hoặc hệ 16.
        return int(str(value), 0)
    except ValueError:
        return None


class FriendlyLogStore:
    """Ghi mỗi event thành một dòng JSON theo Event ID."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._seen: dict[Path, set[str]] = {}

    @staticmethod
    def _to_ecs(record: dict[str, Any], normalized: dict[str, Any] | None) -> dict[str, Any]:
        event_id = int(record["event_id"])
        fields = record.get("event_data") or {}
        normalized = normalized or {}
        account = _first(normalized, "account") or _first(
            fields, "TargetUserName", "SubjectUserName", "AccountName"
        )
        domain = _first(fields, "TargetDomainName", "SubjectDomainName")
        user_sid = _first(fields, "TargetUserSid", "SubjectUserSid")
        ip = _first(normalized, "source_ip") or _first(fields, "IpAddress", "SourceNetworkAddress")
        if ip in ("::1", "127.0.0.1"):
            ip = None
        port = _as_pid(_first(fields, "IpPort", "SourcePort"))
        status = _first(normalized, "status") or _first(fields, "Status", "FailureCode", "SubStatus")

        outcome = "success" if event_id == 4624 else "failure" if event_id in {4625, 4771, 4776} else None
        event_type = "start" if event_id == 4624 else "denied" if event_id in {4625, 4771, 4776} else "change" if event_id == 4740 else "info"
        event: dict[str, Any] = {
            "id": record.get("event_uid"),
            "code": str(event_id),
            "kind": "event",
            "category": ["authentication"],
            "type": [event_type],
            "action": record.get("event_name") or "Windows authentication event",
            "dataset": "windows.security",
            "outcome": outcome,
        }
        result: dict[str, Any] = {
            "@timestamp": iso_vietnam(normalized.get("event_time") or record.get("time_created")),
            "ecs": {"version": "9.5.0"},
            "host": {"name": normalized.get("target_host") or record.get("computer"),
                     "os": {"type": "windows"}},
            "event": {key: value for key, value in event.items() if value is not None},
            "winlog": {
                "channel": record.get("channel") or "Security",
            },
        }
        result["event"]["provider"] = record.get("provider") or "Microsoft-Windows-Security-Auditing"
        result["event"]["created"] = iso_vietnam(
            normalized.get("observed_at")
        ) or now_vietnam().isoformat()
        if account:
            result["user"] = {"name": account}
            if domain:
                result["user"]["domain"] = domain
            if user_sid:
                result["user"]["id"] = user_sid
        if ip:
            result["source"] = {"ip": ip}
            if port is not None:
                result["source"]["port"] = port
        process_name = _first(fields, "ProcessName", "NewProcessName")
        process_id = _as_pid(_first(fields, "ProcessId", "NewProcessId"))
        if process_name or process_id is not None:
            result["process"] = {}
            if process_name:
                result["process"]["executable"] = process_name
            if process_id is not None:
                result["process"]["pid"] = process_id
        logon_type = _first(normalized, "logon_type") or _first(fields, "LogonType")
        if logon_type:
            result["authentication"] = {"type": str(logon_type)}
        if status:
            result["event"]["reason"] = str(status)
        return result

    def append(self, record: dict[str, Any], normalized: dict[str, Any] | None = None) -> Path:
        event_id = int(record["event_id"])
        path = self.root / f"event-{event_id}.log"
        entry = self._to_ecs(record, normalized)
        event_uid = (entry.get("event") or {}).get("id")
        if path not in self._seen:
            # Đọc ID trong file hiện có để tránh lặp log sau khi agent chạy lại.
            seen: set[str] = set()
            if path.exists():
                for line in path.read_text(encoding="utf-8").splitlines():
                    try:
                        existing_id = (json.loads(line).get("event") or {}).get("id")
                    except (json.JSONDecodeError, AttributeError):
                        continue
                    if existing_id:
                        seen.add(str(existing_id))
            self._seen[path] = seen
        if event_uid and str(event_uid) in self._seen[path]:
            return path
        # Mỗi dòng là một event JSON hoàn chỉnh, tiện đọc bằng công cụ xử lý log.
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")))
            stream.write("\n")
        if event_uid:
            self._seen[path].add(str(event_uid))
        return path
