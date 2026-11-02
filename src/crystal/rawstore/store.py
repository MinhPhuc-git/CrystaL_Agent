import json
from pathlib import Path
from typing import Any
import os
import platform
import socket
from crystal.timeutil import now_vietnam, convert_json_times

class RawStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        # Nạp khóa đã ghi để tránh thêm lại event sau khi agent khởi động lại.
        self._seen: dict[str, str] = {}
        with self.path.open("r", encoding="utf-8") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = row.get("source_key")
                if key:
                    self._seen[str(key)] = str(row.get("observed_at") or "")

    def append(self, source: str, source_key: str, payload: dict[str, Any]) -> str:
        if source_key in self._seen:
            # Giữ thời điểm thu thập ban đầu nếu event được đọc lại.
            return self._seen[source_key]
        observed_at = now_vietnam().isoformat()
        stored_payload = convert_json_times(payload)
        row = {"computer": socket.gethostname(), "os": f"{platform.system()} {platform.release()}", 
               "source": source, "source_key": source_key,
               "observed_at": observed_at, "payload": stored_payload}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            f.flush()
        self._seen[source_key] = observed_at
        return observed_at

