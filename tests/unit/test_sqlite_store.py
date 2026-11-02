from crystal.database.store import Database


def test_raw_and_finding_persist(tmp_path):
    db = Database(tmp_path / "pbra.db")
    assert db.save_raw("u1", "Security", "r1", "now", {"event_id":4625})
    assert not db.save_raw("u1", "Security", "r1", "now", {"event_id":4625})
    assert db.raw_seen("u1")
    assert db.db.execute("select count(*) from raw_events").fetchone()[0] == 1
    db.close()
