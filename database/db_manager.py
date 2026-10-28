"""SQLite incident store (rewind.db).

A NEW connection is opened for every call, because Rewind uses several threads
and SQLite connections must not be shared between threads. All queries use
'?' placeholders (parameterized), so odd text can never be run as SQL.
"""
import json
import sqlite3
import time
from contextlib import closing

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      REAL,
    attacker_pid   INTEGER,
    signals        TEXT,
    killed_pids    TEXT,
    restored_files TEXT,
    status         TEXT,
    details        TEXT,
    snapshot_used  TEXT,
    verified       INTEGER
)
"""


def _connect(db_path=None):
    conn = sqlite3.connect(db_path or config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _join(value):
    """Turn a list (or None) into a comma-joined string for storage."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(v) for v in value)
    return str(value)


def init_db(db_path=None):
    """Create the table if it does not exist. Safe to call on every startup."""
    with closing(_connect(db_path)) as conn:
        with conn:
            conn.execute(SCHEMA)


def log_incident(pid, signals, killed_pids, restored_files, status,
                 details=None, snapshot_used=None, verified=False,
                 db_path=None, timestamp=None):
    """Insert one incident row and return its id."""
    if details is None:
        details_text = "{}"
    elif isinstance(details, str):
        details_text = details
    else:
        details_text = json.dumps(details, default=str, sort_keys=True)
    # Make sure the table exists (e.g. if the DB file was deleted while Rewind runs).
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        with conn:
            cur = conn.execute(
                "INSERT INTO incidents (timestamp, attacker_pid, signals, killed_pids, "
                "restored_files, status, details, snapshot_used, verified) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    timestamp if timestamp is not None else time.time(),
                    pid,
                    _join(signals),
                    _join(killed_pids),
                    _join(restored_files),
                    status,
                    details_text,
                    snapshot_used or "",
                    1 if verified else 0,
                ),
            )
            return cur.lastrowid


def get_all_incidents(db_path=None):
    """Return every incident as a list of dicts, newest first."""
    init_db(db_path)
    with closing(_connect(db_path)) as conn:
        rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]
