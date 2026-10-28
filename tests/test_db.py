import sqlite3
import threading

from database import db_manager


def test_init_db_is_safe_to_call_twice(tmp_path):
    db = str(tmp_path / "t.db")
    db_manager.init_db(db)
    db_manager.init_db(db)
    conn = sqlite3.connect(db)
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    conn.close()
    assert "incidents" in tables


def test_log_and_fetch_round_trip(tmp_path):
    db = str(tmp_path / "t.db")
    db_manager.init_db(db)
    row_id = db_manager.log_incident(
        1234, ["DECOY"], [1234], ["document_000.txt"], "RESOLVED",
        details={"note": "x"}, snapshot_used="snapshot_1", verified=True, db_path=db)
    rows = db_manager.get_all_incidents(db)
    assert len(rows) == 1
    r = rows[0]
    assert r["id"] == row_id and r["attacker_pid"] == 1234
    assert r["status"] == "RESOLVED" and r["snapshot_used"] == "snapshot_1"
    assert r["verified"] == 1 and r["timestamp"] > 0


def test_newest_incident_comes_first(tmp_path):
    db = str(tmp_path / "t.db")
    ids = [db_manager.log_incident(i, [], [], [], "RESOLVED", db_path=db) for i in range(3)]
    rows = db_manager.get_all_incidents(db)
    assert [r["id"] for r in rows] == sorted(ids, reverse=True)


def test_lists_are_comma_joined(tmp_path):
    db = str(tmp_path / "t.db")
    db_manager.log_incident(1, ["DECOY", "SPEED"], [100, 101], ["a.txt", "b.txt"],
                            "RESOLVED", db_path=db)
    r = db_manager.get_all_incidents(db)[0]
    assert r["signals"] == "DECOY,SPEED"
    assert r["killed_pids"] == "100,101"
    assert r["restored_files"] == "a.txt,b.txt"


def test_details_are_stored_as_json(tmp_path):
    import json
    db = str(tmp_path / "t.db")
    db_manager.log_incident(1, [], [], [], "PARTIAL",
                            details={"files": 25, "entropy": 7.9}, db_path=db)
    r = db_manager.get_all_incidents(db)[0]
    assert json.loads(r["details"]) == {"files": 25, "entropy": 7.9}


def test_sql_injection_text_is_stored_literally(tmp_path):
    db = str(tmp_path / "t.db")
    evil = "x'); DROP TABLE incidents;--"
    db_manager.log_incident(1, [evil], [], [], evil, db_path=db)
    rows = db_manager.get_all_incidents(db)
    assert len(rows) == 1 and rows[0]["status"] == evil


def test_concurrent_writes_from_many_threads(tmp_path):
    db = str(tmp_path / "t.db")
    db_manager.init_db(db)
    threads = [threading.Thread(
        target=db_manager.log_incident,
        args=(i, ["SPEED"], [i], [], "RESOLVED"), kwargs={"db_path": db})
        for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(db_manager.get_all_incidents(db)) == 10


def test_get_all_on_fresh_database_returns_empty_list(tmp_path):
    assert db_manager.get_all_incidents(str(tmp_path / "fresh.db")) == []


def test_log_incident_works_on_a_brand_new_database_file(tmp_path):
    db = str(tmp_path / "new.db")  # no init_db() call on purpose
    db_manager.log_incident(1, ["DECOY"], [], [], "RESOLVED", db_path=db)
    assert len(db_manager.get_all_incidents(db)) == 1


def test_log_incident_recovers_if_the_database_file_is_deleted(tmp_path):
    import os
    db = str(tmp_path / "t.db")
    db_manager.log_incident(1, [], [], [], "RESOLVED", db_path=db)
    os.remove(db)  # simulates generate_samples.py resetting the DB mid-run
    db_manager.log_incident(2, [], [], [], "RESOLVED", db_path=db)
    rows = db_manager.get_all_incidents(db)
    assert len(rows) == 1 and rows[0]["attacker_pid"] == 2
