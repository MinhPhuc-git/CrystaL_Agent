import json
import sqlite3
from pathlib import Path
from crystal.normalization.auth import AuthEvent
from crystal.risk.rules.bruteforce import Finding
from crystal.timeutil import convert_json_times, iso_vietnam, now_vietnam


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS raw_events(event_uid TEXT PRIMARY KEY, source TEXT NOT NULL, source_key TEXT NOT NULL, observed_at TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS auth_events(event_uid TEXT PRIMARY KEY REFERENCES raw_events(event_uid), event_id INTEGER NOT NULL, event_time TEXT NOT NULL, target_host TEXT NOT NULL, account TEXT NOT NULL, source_ip TEXT, logon_type TEXT, status TEXT, source TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS findings(finding_id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL, entity_key TEXT NOT NULL, severity TEXT NOT NULL, score INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, count INTEGER NOT NULL, evidence_ids TEXT NOT NULL, details TEXT NOT NULL, UNIQUE(rule_id,entity_key,first_seen));
        CREATE INDEX IF NOT EXISTS ix_findings_current ON findings(status,severity);
        CREATE TABLE IF NOT EXISTS collector_health(source TEXT PRIMARY KEY, state TEXT NOT NULL, last_error TEXT, checked_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS collector_checkpoints(collector_id TEXT PRIMARY KEY, record_id INTEGER NOT NULL, event_time TEXT, updated_at TEXT NOT NULL);
        """)
        self.db.commit()
        checkpoint_columns = {row[1] for row in self.db.execute("PRAGMA table_info(collector_checkpoints)")}
        if "event_time" not in checkpoint_columns:
            self.db.execute("ALTER TABLE collector_checkpoints ADD COLUMN event_time TEXT")
            self.db.commit()
        self.timestamp_migration_needed = self._migrate_timestamps_to_vietnam()
        self._seed_security_checkpoint()

    def _migrate_timestamps_to_vietnam(self) -> bool:
        self.db.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        # Chạy chuyển múi giờ một lần; phiên bản 2 đánh dấu dữ liệu đã đổi xong.
        if self.db.execute("SELECT 1 FROM schema_migrations WHERE version=2").fetchone():
            return False

        # Chuyển cả thời điểm ngoài cột lẫn timestamp nằm trong raw payload.
        for uid, observed, payload_text in self.db.execute(
            "SELECT event_uid, observed_at, payload FROM raw_events"
        ).fetchall():
            try:
                payload = convert_json_times(json.loads(payload_text))
                serialized = json.dumps(payload, ensure_ascii=False)
            except (TypeError, json.JSONDecodeError):
                serialized = payload_text
            self.db.execute("UPDATE raw_events SET observed_at=?, payload=? WHERE event_uid=?",
                            (iso_vietnam(observed) or observed, serialized, uid))
        for table, columns, key in (
            ("auth_events", ("event_time",), "event_uid"),
            ("findings", ("first_seen", "last_seen"), "finding_id"),
            ("collector_health", ("checked_at",), "source"),
        ):
            select_cols = ",".join((key, *columns))
            for row in self.db.execute(f"SELECT {select_cols} FROM {table}").fetchall():
                values = [iso_vietnam(value) or value for value in row[1:]]
                assignments = ",".join(f"{column}=?" for column in columns)
                self.db.execute(f"UPDATE {table} SET {assignments} WHERE {key}=?", (*values, row[0]))
        self.db.execute("INSERT INTO schema_migrations(version, applied_at) VALUES(2, ?)",
                        (now_vietnam().isoformat(),))
        self.db.commit()
        return True

    def raw_seen(self, uid: str) -> bool:
        return self.db.execute("SELECT 1 FROM raw_events WHERE event_uid=?", (uid,)).fetchone() is not None

    def checkpoint(self, collector_id: str) -> tuple[int, str | None]:
        row = self.db.execute("SELECT record_id,event_time FROM collector_checkpoints WHERE collector_id=?",
                              (collector_id,)).fetchone()
        return (int(row[0]), row[1]) if row else (0, None)

    def _seed_security_checkpoint(self) -> None:
        if self.db.execute("SELECT 1 FROM collector_checkpoints WHERE collector_id='Windows-Security'").fetchone():
            return
        # Tạo checkpoint từ event cũ để lần nâng cấp đầu không quét lại toàn bộ log.
        best_record_id = 0
        best_event_time: str | None = None
        rows = self.db.execute(
            "SELECT r.payload FROM raw_events r JOIN auth_events a ON a.event_uid=r.event_uid "
            "WHERE r.source='Windows-Security'"
        ).fetchall()
        for (payload_text,) in rows:
            try:
                payload = json.loads(payload_text)
                record_id = int(payload.get("record_id") or 0)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
            if record_id > best_record_id:
                best_record_id = record_id
                best_event_time = payload.get("time_created")
        if best_record_id:
            self.save_checkpoint("Windows-Security", best_record_id, best_event_time)

    def save_checkpoint(self, collector_id: str, record_id: int, event_time: str | None) -> None:
        self.db.execute("INSERT INTO collector_checkpoints(collector_id,record_id,event_time,updated_at) VALUES(?,?,?,?) ON CONFLICT(collector_id) DO UPDATE SET record_id=excluded.record_id,event_time=excluded.event_time,updated_at=excluded.updated_at",
                        (collector_id, int(record_id), iso_vietnam(event_time) if event_time else None,
                         now_vietnam().isoformat()))
        self.db.commit()

    def save_raw(self, uid: str, source: str, source_key: str, observed: str, payload: dict) -> bool:
        # Khóa chính event_uid giúp lần ghi lại cùng event không tạo bản sao.
        cur = self.db.execute("INSERT OR IGNORE INTO raw_events VALUES(?,?,?,?,?)",
                              (uid, source, source_key, iso_vietnam(observed) or observed,
                               json.dumps(convert_json_times(payload), ensure_ascii=False)))
        self.db.commit()
        return cur.rowcount == 1

    def save_auth(self, e: AuthEvent) -> None:
        self.db.execute("INSERT OR IGNORE INTO auth_events VALUES(?,?,?,?,?,?,?,?,?)",
                        (e.event_uid,e.event_id,e.event_time.isoformat(),e.target_host,e.account,e.source_ip,e.logon_type,e.status,e.source))
        self.db.commit()

    def save_finding(self, f: Finding) -> None:
        key = f"{f.target_host}|{f.account}|{f.source_ip or 'unknown'}"
        self.db.execute("INSERT OR IGNORE INTO findings(rule_id,entity_key,severity,score,status,first_seen,last_seen,count,evidence_ids,details) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (f.rule_id,key,f.severity,f.score,"open",f.window_start.isoformat(),f.window_end.isoformat(),f.count,json.dumps(f.evidence_ids),json.dumps({"reason":f.reason})))
        self.db.commit()

    def health(self, source: str, state: str, error: str | None = None) -> None:
        self.db.execute("INSERT INTO collector_health VALUES(?,?,?,?) ON CONFLICT(source) DO UPDATE SET state=excluded.state,last_error=excluded.last_error,checked_at=excluded.checked_at",
                        (source,state,error,now_vietnam().isoformat()))
        self.db.commit()

    def close(self) -> None:
        self.db.close()
