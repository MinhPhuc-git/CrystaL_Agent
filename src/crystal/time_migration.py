import json
from pathlib import Path
from typing import Any

from crystal.timeutil import convert_json_times


def _rewrite_json_lines(path: Path, *, key_path: tuple[str, ...]) -> int:
    seen: set[str] = set()
    output: list[str] = []
    removed = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item: Any = json.loads(line)
        except json.JSONDecodeError:
            # Giữ dòng lỗi nguyên trạng để việc đổi thời gian không làm mất dữ liệu.
            output.append(line)
            continue
        item = convert_json_times(item)
        key: Any = item
        for name in key_path:
            key = key.get(name) if isinstance(key, dict) else None
        if key:
            key = str(key)
            if key in seen:
                removed += 1
                continue
            seen.add(key)
        output.append(json.dumps(item, ensure_ascii=False, separators=(",", ":")))

    # Ghi xong file tạm rồi thay file gốc để tránh để lại file dở nếu bị ngắt.
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text("\n".join(output) + ("\n" if output else ""), encoding="utf-8", newline="\n")
    temp.replace(path)
    return removed


def migrate_event_files(raw_path: str | Path, logs_dir: str | Path) -> dict[str, int]:
    """Đổi múi giờ và loại event trùng trong các file raw, normalized."""
    raw_path = Path(raw_path)
    logs_dir = Path(logs_dir)
    removed = {"raw": 0, "logs": 0}
    raw_files = sorted(set(raw_path.parent.glob("*.jsonl")) | set(raw_path.parent.glob("*.json")))
    for path in raw_files:
        removed["raw"] += _rewrite_json_lines(path, key_path=("source_key",))
    for path in sorted(logs_dir.glob("event-*.log")):
        removed["logs"] += _rewrite_json_lines(path, key_path=("event", "id"))
    return removed
