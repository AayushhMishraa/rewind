"""JSON-lines logger (rule R3: every action is traceable to its signals).

Each call writes ONE line of JSON to rewind.log containing at least:
incident_trace_id, signals, pid, action.
"""
import json
import threading
import time
import uuid

import config

_lock = threading.Lock()   # several threads log at once; the lock keeps lines from mixing
_log_path = None           # None means "use config.LOG_PATH" (tests override this)


def set_log_path(path):
    """Point the logger at a different file (used by tests). None restores the default."""
    global _log_path
    _log_path = path


def get_log_path():
    return _log_path or config.LOG_PATH


def new_trace_id():
    """A short unique id that ties together every log line of one incident."""
    return uuid.uuid4().hex[:12]


def log(action, incident_trace_id=None, signals=None, pid=None, **extra):
    """Append one JSON line to the log and return the record that was written."""
    record = {
        "ts": time.time(),
        "action": action,
        "incident_trace_id": incident_trace_id,
        "signals": list(signals) if signals else [],
        "pid": pid,
    }
    # Extra details are allowed, but they can never overwrite the core fields.
    for key, value in extra.items():
        if key not in record:
            record[key] = value
    line = json.dumps(record, default=str, sort_keys=True)
    with _lock:
        with open(get_log_path(), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    return record
