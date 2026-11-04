import json
import os
import subprocess

import pytest

from dashboard.app import ELEVATED, NORMAL, OFFLINE, RESPONDING, create_app, derive_state
from database import db_manager

NOW = 1800000000.0


def rec(action, dt, trace=None, signals=(), pid=None, **extra):
    """One fake rewind.log line, `dt` seconds from 'now'."""
    r = {"ts": NOW + dt, "action": action, "incident_trace_id": trace,
         "signals": list(signals), "pid": pid}
    r.update(extra)
    return r


def make_app(tmp_path, records=(), marker=True, allow=True):
    """A dashboard wired to temporary files only. Returns (test client, sandbox folder, db path)."""
    folder = tmp_path / "protected"
    folder.mkdir(parents=True)
    if marker:
        (folder / ".REWIND_SANDBOX").write_text("marker")
    (folder / "document_000.txt").write_text("hello " * 100)
    (tmp_path / "rewind.log").write_text("".join(json.dumps(r) + "\n" for r in records))
    db = str(tmp_path / "t.db")
    app = create_app(protected_dir=str(folder), db_path=db, log_path=str(tmp_path / "rewind.log"),
                     allow_simulate=allow, clock=lambda: NOW)
    return app.test_client(), folder, db


class FakeProc:
    pid = 4321
    running = False

    def poll(self):
        return None if FakeProc.running else 0


@pytest.fixture
def popen_calls(monkeypatch):
    """Replaces subprocess.Popen so no real simulator ever starts. Returns the list of commands."""
    calls = []
    FakeProc.running = False

    def fake_popen(cmd, **kwargs):
        calls.append(cmd)
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return calls


# ---------------------------------------------------------------- the pages and the api
def test_routes_return_200(tmp_path):
    client, folder, db = make_app(tmp_path)
    for url in ("/", "/incidents", "/api/incidents", "/api/status", "/static/style.css"):
        assert client.get(url).status_code == 200, url


def test_api_incidents_empty_db(tmp_path):
    client, folder, db = make_app(tmp_path)
    assert client.get("/api/incidents").get_json() == []          # there is no database file yet
    db_manager.init_db(db)
    assert client.get("/api/incidents").get_json() == []          # database exists but is empty


def test_api_incidents_after_insert(tmp_path):
    client, folder, db = make_app(tmp_path)
    db_manager.log_incident(4242, ["DECOY"], [4242], ["a.txt", "b.txt"], "RESOLVED",
                            details={"response": {"trace_id": "abc123def456"}},
                            snapshot_used="snapshot_1", verified=True, db_path=db)
    rows = client.get("/api/incidents").get_json()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == 1 and row["attacker_pid"] == 4242
    assert row["signals"] == ["DECOY"] and row["killed_pids"] == ["4242"]
    assert row["restored_count"] == 2 and row["restored_files"] == ["a.txt", "b.txt"]
    assert row["status"] == "RESOLVED" and row["verified"] is True
    assert row["trace_id"] == "abc123def456" and row["trace_short"] == "abc123de"
    assert row["snapshot_used"] == "snapshot_1" and row["time"]


# ---------------------------------------------------------------- the simulate buttons
def test_simulate_button_refuses_without_sandbox_marker(tmp_path, popen_calls):
    client, folder, db = make_app(tmp_path, marker=False)
    resp = client.post("/api/simulate", json={"variant": "v1"})
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["ok"] is False and "REWIND_SANDBOX" in body["error"]
    assert popen_calls == []                                      # nothing was launched


def test_simulate_button_launches_in_marked_sandbox(tmp_path, popen_calls):
    client, folder, db = make_app(tmp_path)
    expected = {"v1": ("ransomware_v1.py", False), "v2": ("ransomware_v2.py", False),
                "v2weak": ("ransomware_v2.py", True)}
    for variant, (script, weak) in expected.items():
        resp = client.post("/api/simulate", json={"variant": variant,
                                                  "avoid_decoys": variant == "v2weak"})
        body = resp.get_json()
        assert resp.status_code == 200 and body["ok"] is True and body["pid"] == 4321
        cmd = popen_calls[-1]
        assert os.path.basename(cmd[1]) == script
        assert cmd[cmd.index("--target") + 1] == str(folder)
        assert ("--weak" in cmd) == weak
        assert ("--avoid-decoys" in cmd) == (variant == "v2weak")
    assert len(popen_calls) == 3
    FakeProc.running = True                                       # the last one is still going
    again = client.post("/api/simulate", json={"variant": "v1"})
    assert again.status_code == 409 and len(popen_calls) == 3     # only one at a time


def test_simulate_needs_the_switch_json_and_a_local_host(tmp_path, popen_calls):
    off, _, _ = make_app(tmp_path / "off", allow=False)
    resp = off.post("/api/simulate", json={"variant": "v1"})
    assert resp.status_code == 403 and resp.get_json()["ok"] is False
    on, _, _ = make_app(tmp_path / "on", allow=True)
    assert on.post("/api/simulate", data={"variant": "v1"}).status_code == 415   # plain web form
    assert on.post("/api/simulate", json={"variant": "rm -rf /"}).status_code == 400
    assert on.get("/", base_url="http://evil.example.com").status_code == 403    # wrong Host header
    assert popen_calls == []


# ---------------------------------------------------------------- status light and timeline
def test_status_light_follows_the_log(tmp_path):
    start, beat = rec("rewind_started", -100), rec("snapshot_taken", -10)
    cases = [
        ([], OFFLINE),
        ([start, beat], NORMAL),
        ([start, beat, rec("verdict_suspicious", -3, signals=["SPEED"])], ELEVATED),
        ([start, beat, rec("verdict_suspicious", -3), rec("response_start", -2)], RESPONDING),
        ([start, beat, rec("response_start", -2), rec("response_end", -1)], NORMAL),
        ([start, beat, rec("verdict_suspicious", -3), rec("calmed_down", -1)], NORMAL),
        ([start, beat, rec("rewind_stopped", -1)], OFFLINE),
        ([rec("rewind_started", -1000), rec("snapshot_taken", -500)], OFFLINE),   # no heartbeat
    ]
    for records, expected in cases:
        assert derive_state(records, NOW)[0] == expected, expected
    client, folder, db = make_app(tmp_path, records=[start, beat, rec("response_start", -2)])
    body = client.get("/api/status").get_json()
    assert body["state"] == "RESPONDING" and body["engine_running"] is True
    assert body["files_watched"] == 1 and body["last_incident"] is None
    assert body["simulate_enabled"] is True and body["sandbox_ok"] is True


def test_incident_timeline_is_built_from_the_log(tmp_path):
    trace, sig = "abc123def456", ["SPEED", "ENTROPY"]
    lines = [
        rec("verdict_confirmed", -5, trace, sig, 4242, path="/x/<img src=x onerror=alert(1)>.txt"),
        rec("response_start", -4.9, trace, sig, 4242),
        rec("kill_report", -4.5, trace, sig, 4242, killed=[4242], failed=[]),
        rec("quiet_wait", -3, trace, sig, None, quiet=True),
        rec("restore_start", -2.8, trace, snapshot="snapshot_1"),
        rec("restore_file", -2.7, trace, path="document_000.txt"),
        rec("restore_done", -2.5, trace, snapshot="snapshot_1", restored=25, failed=0,
            quarantined=0, verified=True),
        rec("response_end", -2.4, trace, sig, 4242, status="RESOLVED"),
        rec("response_start", -1, "zzzzzzzzzzzz"),                # a different incident: ignored
    ]
    client, folder, db = make_app(tmp_path, records=lines)
    db_manager.log_incident(4242, sig, [4242], ["document_000.txt"], "RESOLVED",
                            details={"response": {"trace_id": trace}}, snapshot_used="snapshot_1",
                            verified=True, db_path=db)
    resp = client.get("/incidents/1")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    for phase in ("DETECTED", "RESPONSE", "RESTORE", "VERIFIED"):
        assert phase in html
    assert "25 file(s) decrypted/restored" in html and "snapshot_1" in html
    assert "Integrity check passed" in html
    assert "<img src=x" not in html and "&lt;img src=x" in html   # file names are shown safely
    assert client.get("/incidents/999").status_code == 404
