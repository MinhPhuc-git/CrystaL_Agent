import argparse
import json
import os
import signal
import sys
from datetime import timedelta
from pathlib import Path

from crystal.collectors.windows.auth.security_events import SecurityEventCollector
from crystal.database.store import Database
from crystal.normalization.auth import normalize_auth
from crystal.rawstore.store import RawStore
from crystal.rawstore.friendly import FriendlyLogStore
from crystal.risk.rules.bruteforce import BruteForceRule
from crystal.time_migration import migrate_event_files


def _load_project_env() -> None:
    # Biến môi trường của Windows được ưu tiên hơn giá trị trong file .env.
    env_path = Path(__file__).resolve().parents[3] / ".env"
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not key.isidentifier() or not value:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _int_env(name: str, default: int, minimum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value >= minimum else default


def _db_enabled() -> bool:
    return os.environ.get("CRYSTAL_DB_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


def _root() -> Path:
    _load_project_env()
    project_root = Path(__file__).resolve().parents[3]
    configured = os.environ.get("CRYSTAL_DATA_DIR")
    if configured:
        path = Path(configured).expanduser()
        return path.resolve() if path.is_absolute() else (project_root / path).resolve()
    # Nếu chưa cấu hình, lưu dữ liệu trong thư mục data của CrystaL.
    return project_root / "data"


def _data_path(root: Path, variable: str, default: str) -> Path:
    # Đường dẫn tương đối được tính từ thư mục dữ liệu, đường dẫn tuyệt đối giữ nguyên.
    configured = os.environ.get(variable, "").strip()
    path = Path(configured).expanduser() if configured else Path(default)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _open_database(db_path: Path, raw_path: Path, logs_dir: Path) -> Database:
    db = Database(db_path)
    if db.timestamp_migration_needed:
        removed = migrate_event_files(raw_path=raw_path, logs_dir=logs_dir)
        print(f"Migrated stored timestamps to Vietnam time; removed duplicates: {removed}", flush=True)
    return db


def run_live() -> int:
    root = _root()
    db_path = _data_path(root, "CRYSTAL_DB_PATH", "db/crystal.sqlite3")
    raw_path = _data_path(root, "CRYSTAL_RAW_LOG_PATH", "raw/security-events.jsonl")
    logs_dir = _data_path(root, "CRYSTAL_NORMALIZED_LOG_DIR", "logs")
    db = _open_database(db_path, raw_path, logs_dir) if _db_enabled() else None
    raw = RawStore(raw_path)
    friendly = FriendlyLogStore(logs_dir)
    rule = BruteForceRule(
        threshold=_int_env("CRYSTAL_BRUTEFORCE_THRESHOLD", 5, 2),
        window=timedelta(seconds=_int_env("CRYSTAL_BRUTEFORCE_WINDOW_SECONDS", 300, 1)),
    )
    print(f"Data directory: {root.resolve()}", flush=True)
    if db is None:
        print("SQLite: disabled; raw/normalized logs and in-memory risk analysis remain active.", flush=True)
    print("Reading Security authentication events (4624, 4625, 4740, 4771, 4776). Ctrl+C to stop.", flush=True)
    try:
        if db is not None:
            db.health("Windows-Security", "running")
            checkpoint_id, checkpoint_time = db.checkpoint("Windows-Security")
        else:
            # Không có checkpoint thì quét lại 24 giờ; RawStore bỏ qua event đã lưu.
            checkpoint_id, checkpoint_time = 0, None
        print(f"Resume checkpoint: RecordID={checkpoint_id}, time={checkpoint_time or '24-hour initial scan'}", flush=True)
        for record in SecurityEventCollector().stream(checkpoint_id, checkpoint_time):
            uid = record["event_uid"]
            record_id = int(record.get("record_id") or 0)
            if db is None and raw.contains(uid):
                continue
            observed = raw.append(record["source"], uid, record)
            auth = normalize_auth(record)
            normalized = auth.as_dict() if auth else None
            if normalized is not None:
                normalized["observed_at"] = observed
            if db is not None and db.raw_seen(uid):
                if auth is not None:
                    db.save_auth(auth)
                    friendly.append(record, normalized)
                db.save_checkpoint("Windows-Security", record_id,
                                   normalized.get("event_time") if normalized else record.get("time_created"))
                continue
            if db is not None and not db.save_raw(uid, record["source"], uid, observed, record):
                db.save_checkpoint("Windows-Security", record_id,
                                   normalized.get("event_time") if normalized else record.get("time_created"))
                continue
            if auth is None:
                if db is not None:
                    db.save_checkpoint("Windows-Security", record_id, record.get("time_created"))
                continue
            if db is not None:
                db.save_auth(auth)
            friendly_path = friendly.append(record, normalized)
            print(f"Normalized event grouped under ID {record['event_id']}: {friendly_path}", flush=True)
            finding = rule.process(auth)
            if finding:
                print(json.dumps({"finding": finding.rule_id, "severity": finding.severity,
                                  "score": finding.score, "account": finding.account,
                                  "source_ip": finding.source_ip, "target_host": finding.target_host,
                                  "failed_logons": finding.count,
                                  "evidence_ids": finding.evidence_ids}, ensure_ascii=False))
            if db is not None:
                db.save_checkpoint("Windows-Security", record_id, normalized.get("event_time"))
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        if db is not None:
            db.health("Windows-Security", "error", str(exc))
        print(f"collector error: {exc}", file=sys.stderr)
        return 2
    finally:
        if db is not None:
            db.health("Windows-Security", "stopped")
            db.close()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="crystal-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="collect local Windows authentication events and analyze brute force")
    sub.add_parser("status", help="show local database/tracking summary")
    args = parser.parse_args()
    if args.command == "run":
        raise SystemExit(run_live())
    root = _root()
    if not _db_enabled():
        print(json.dumps({"database": "disabled", "data_directory": str(root)}, indent=2))
        return
    db_path = _data_path(root, "CRYSTAL_DB_PATH", "db/crystal.sqlite3")
    raw_path = _data_path(root, "CRYSTAL_RAW_LOG_PATH", "raw/security-events.jsonl")
    logs_dir = _data_path(root, "CRYSTAL_NORMALIZED_LOG_DIR", "logs")
    db = _open_database(db_path, raw_path, logs_dir)
    count = db.db.execute("SELECT count(*) FROM raw_events").fetchone()[0]
    cases = db.db.execute("SELECT count(*) FROM findings WHERE status='open'").fetchone()[0]
    print(json.dumps({"raw_events": count, "open_findings": cases, "database": str(db.path)}, indent=2))
    print(json.dumps({"security_checkpoint": db.checkpoint("Windows-Security")}, ensure_ascii=False))
    db.close()


if __name__ == "__main__":
    main()
