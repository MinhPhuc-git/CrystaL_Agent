from datetime import datetime, timedelta, timezone
from typing import Any


VIETNAM_TZ = timezone(timedelta(hours=7), "Asia/Ho_Chi_Minh")


def now_vietnam() -> datetime:
    return datetime.now(VIETNAM_TZ)


def to_vietnam(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        stamp = value
    else:
        try:
            stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if stamp.tzinfo is None:
        # Timestamp không có múi giờ được xem là UTC để tránh lệch giờ theo máy chạy agent.
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(VIETNAM_TZ)


def iso_vietnam(value: Any) -> str | None:
    stamp = to_vietnam(value)
    return stamp.isoformat() if stamp is not None else None


_TIME_KEYS = {
    "@timestamp", "time_created", "event_time", "time_utc", "time", "created",
    "observed_at", "created_at",
    "checked_at", "first_seen", "last_seen", "window_start", "window_end",
    "processed_at", "last_success_at", "last_error_at", "started_at", "ended_at",
}


def convert_json_times(value: Any) -> Any:
    """Đổi các trường thời gian đã biết trong cấu trúc JSON sang giờ Việt Nam."""
    if isinstance(value, dict):
        converted = {}
        for key, child in value.items():
            if key.lower() in _TIME_KEYS and isinstance(child, str):
                converted[key] = iso_vietnam(child) or child
            else:
                converted[key] = convert_json_times(child)
        return converted
    if isinstance(value, list):
        return [convert_json_times(item) for item in value]
    return value
