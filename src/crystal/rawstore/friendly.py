from pathlib import Path
import json
from datetime import datetime
from typing import Any
from crystal.timeutil import now_vietnam, iso_vietnam
from crystal.normalization.connect_type import CONNECT_TYPE_NAMES


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


def _status_code(value: Any) -> str | None:
    if value in (None, "", "-"):
        return None
    text = str(value).strip()
    try:
        number = int(text, 16 if text.lower().startswith("0x") else 10)
    except ValueError:
        return text
    if number < 0:
        number &= 0xFFFFFFFF
    return f"0x{number:08X}"


def _time_seconds(value: Any) -> str | None:
    stamp = iso_vietnam(value)
    if not stamp:
        return None
    return datetime.fromisoformat(stamp).replace(microsecond=0).isoformat(timespec="seconds")


class FriendlyLogStore:
    """Ghi các trường cần thiết thành một dòng JSON theo Event ID."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._compact_legacy_logs()
        self._seen: dict[Path, set[str]] = {}

    @staticmethod
    def _from_legacy(entry: dict[str, Any]) -> dict[str, Any]:
        event = entry.get("event") or {}
        host = entry.get("host") or {}
        user = entry.get("user") or {}
        source = entry.get("source") or {}
        process = entry.get("process") or {}
        winlog = entry.get("winlog") or {}
        auth = entry.get("authentication") or {}
        event_uid = event.get("id")
        event_id = _as_pid(event.get("code"))
        record_id = _as_pid(winlog.get("record_id"))
        if record_id is None and event_uid:
            parts = str(event_uid).split(":")
            if len(parts) >= 3:
                record_id = _as_pid(parts[-2])
        logon_type = _as_pid(auth.get("type"))
        compact: dict[str, Any] = {
            "schema_version": 3,
            "event_uid": event_uid,
            "event_id": event_id,
            "event_name": event.get("action"),
            "event_time": _time_seconds(entry.get("@timestamp")),
            "observed_at": _time_seconds(event.get("created")),
            "host": host.get("name"),
            "channel": winlog.get("channel"),
            "outcome": event.get("outcome"),
        }
        optional = {
            "record_id": record_id,
            "account": user.get("name"),
            "account_domain": user.get("domain"),
            "account_sid": user.get("id"),
            "source_ip": source.get("ip"),
            "source_port": _as_pid(source.get("port")),
            "process_name": process.get("executable"),
            "process_id": _as_pid(process.get("pid")),
            "logon_type": logon_type,
            "status_code": _status_code(event.get("reason")),
        }
        if logon_type is not None:
            optional["connect_type"] = CONNECT_TYPE_NAMES.get(str(logon_type))
        compact.update({key: value for key, value in optional.items() if value is not None})
        return {key: value for key, value in compact.items() if value is not None}

    def _compact_legacy_logs(self) -> None:
        """Chuyển log ECS cũ sang dạng gọn một lần, không đụng tới raw log."""
        for path in self.root.glob("event-*.log"):
            try:
                with path.open("r", encoding="utf-8") as source:
                    first = next((line for line in source if line.strip()), "")
                sample = json.loads(first) if first else {}
            except (OSError, json.JSONDecodeError):
                continue
            if sample.get("schema_version") == 3:
                continue

            temp = path.with_suffix(path.suffix + ".tmp")
            try:
                with path.open("r", encoding="utf-8") as source, temp.open(
                    "w", encoding="utf-8", newline="\n"
                ) as target:
                    for line in source:
                        try:
                            old = json.loads(line)
                        except json.JSONDecodeError:
                            target.write(line if line.endswith("\n") else line + "\n")
                            continue
                        if old.get("schema_version") in {1, 2}:
                            compact = dict(old)
                            compact["schema_version"] = 3
                            compact["event_time"] = _time_seconds(compact.get("event_time"))
                            compact["observed_at"] = _time_seconds(compact.get("observed_at"))
                            status = _status_code(compact.get("status_code"))
                            if status:
                                compact["status_code"] = status
                            else:
                                compact.pop("status_code", None)
                        else:
                            compact = self._from_legacy(old)
                        target.write(json.dumps(compact, ensure_ascii=False, separators=(",", ":")) + "\n")
                temp.replace(path)
            except OSError:
                temp.unlink(missing_ok=True)

    @staticmethod
    def _to_normalized(record: dict[str, Any], normalized: dict[str, Any] | None) -> dict[str, Any]:
        event_id = int(record["event_id"])
        fields = record.get("event_data") or {}
        normalized = normalized or {}
        account = _first(normalized, "account") or _first(
            fields, "TargetUserName", "SubjectUserName", "AccountName"
        )
        domain = _first(fields, "TargetDomainName", "SubjectDomainName")
        user_sid = _first(fields, "TargetUserSid", "SubjectUserSid")
        ip = _first(normalized, "source_ip") or _first(fields, "IpAddress", "SourceNetworkAddress")
        if ip == "-":
            ip = None
        port = _as_pid(_first(fields, "IpPort", "SourcePort"))
        status = _first(normalized, "status") or _first(fields, "Status", "FailureCode", "SubStatus")
        logon_type = _as_pid(_first(normalized, "logon_type") or _first(fields, "LogonType"))
        record_id = _as_pid(record.get("record_id"))
        outcome = "success" if event_id == 4624 else "failure" if event_id in {4625, 4771, 4776} else "change" if event_id == 4740 else "info"
        result: dict[str, Any] = {
            "schema_version": 3,
            "event_uid": record.get("event_uid"),
            "event_id": event_id,
            "event_name": record.get("event_name") or "Windows authentication event",
            "event_time": _time_seconds(normalized.get("event_time") or record.get("time_created")),
            "observed_at": _time_seconds(normalized.get("observed_at")) or _time_seconds(now_vietnam()),
            "host": normalized.get("target_host") or record.get("computer"),
            "channel": record.get("channel") or "Security",
            "outcome": outcome,
        }
        if record_id is not None:
            result["record_id"] = record_id
        if account:
            result["account"] = account
        if domain:
            result["account_domain"] = domain
        if user_sid:
            result["account_sid"] = user_sid
        if ip:
            result["source_ip"] = ip
        if port is not None:
            result["source_port"] = port
        process_name = _first(fields, "ProcessName", "NewProcessName")
        process_id = _as_pid(_first(fields, "ProcessId", "NewProcessId"))
        if process_name:
            result["process_name"] = process_name
        if process_id is not None:
            result["process_id"] = process_id
        if logon_type is not None:
            result["logon_type"] = logon_type
            connect_type = CONNECT_TYPE_NAMES.get(str(logon_type))
            if connect_type:
                result["connect_type"] = connect_type
        if status:
            result["status_code"] = _status_code(status)
        client_host = _first(fields, "Workstation", "WorkstationName", "CallerComputerName")
        if client_host:
            result["client_host"] = client_host
        service_name = _first(fields, "ServiceName")
        if service_name:
            result["service_name"] = service_name
        return result

    def append(self, record: dict[str, Any], normalized: dict[str, Any] | None = None) -> Path:
        event_id = int(record["event_id"])
        path = self.root / f"event-{event_id}.log"
        entry = self._to_normalized(record, normalized)
        event_uid = entry.get("event_uid")
        if path not in self._seen:
            # Đọc ID trong file hiện có để tránh lặp log sau khi agent chạy lại.
            seen: set[str] = set()
            if path.exists():
                for line in path.read_text(encoding="utf-8").splitlines():
                    try:
                        existing = json.loads(line)
                        existing_id = existing.get("event_uid") or (existing.get("event") or {}).get("id")
                    except (json.JSONDecodeError, AttributeError):
                        continue
                    if existing_id:
                        seen.add(str(existing_id))
            self._seen[path] = seen
        if event_uid and str(event_uid) in self._seen[path]:
            return path
        # Mỗi dòng chỉ giữ các trường cần cho truy vấn và phân tích.
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")))
            stream.write("\n")
        if event_uid:
            self._seen[path].add(str(event_uid))
        return path
