from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from crystal.normalization.auth import AuthEvent


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    score: int
    account: str
    source_ip: str | None
    target_host: str
    count: int
    window_start: datetime
    window_end: datetime
    evidence_ids: tuple[str, ...]
    reason: str


class BruteForceRule:
    """Chỉ phát hiện và báo rủi ro, không khóa tài khoản hay chặn kết nối."""
    def __init__(self, threshold: int = 5, window: timedelta = timedelta(minutes=5)) -> None:
        if threshold < 2 or window.total_seconds() <= 0:
            raise ValueError("threshold must be >=2 and window must be positive")
        self.threshold, self.window = threshold, window
        self._events: dict[tuple[str, str, str], deque] = defaultdict(deque)
        self._emitted: set[tuple[str, str, str, str]] = set()

    def process(self, event: AuthEvent) -> Finding | None:
        if event.event_id != 4625:
            return None
        # Gom riêng theo máy, tài khoản và IP; chuẩn hóa chữ hoa/thường để không tách nhầm nhóm.
        account = event.account.strip().casefold()
        host = event.target_host.strip().casefold()
        source = (event.source_ip or "unknown-source").strip().casefold()
        key = (host, account, source)
        bucket = self._events[key]
        cutoff = event.event_time - self.window
        # Giữ lại các lần thất bại còn nằm trong cửa sổ thời gian đang xét.
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()
        if not any(item[1] == event.event_uid for item in bucket):
            bucket.append((event.event_time, event.event_uid))
        if len(bucket) < self.threshold:
            return None
        window_start, window_end = bucket[0][0], bucket[-1][0]
        fingerprint = (*key, window_start.isoformat())
        if fingerprint in self._emitted:
            return None
        # Chỉ phát một finding cho cùng nhóm và cùng cửa sổ bắt đầu.
        self._emitted.add(fingerprint)
        return Finding("brute_force_suspected", "high", 70, account,
                       event.source_ip, host, len(bucket), window_start, window_end,
                       tuple(item[1] for item in bucket),
                       f"{len(bucket)} failed logons for this account/source within {self.window}")
