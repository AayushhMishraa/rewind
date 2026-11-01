"""Acceptance scenarios: the REAL Rewind pipeline against REAL attacker processes.

SETUP (same pattern as test_integration.py): every test gets its own temporary sandbox,
database, log and backups, builds a RewindApp pointed at them, and starts it. The attackers
are separate processes. Nothing in the real project folder is touched, and no production
code needs a "test mode":
  S4 uses SnapshotManager.start_periodic(interval=1)      (its own argument)
  S6 sets watcher.attribute = False, so every event is "unknown process" (pid -1)
  S1-live runs the dashboard in-process with Flask's test client, using the real env gate

Each test is independent (fresh app, fresh files), so there is no shared state to clean up.
(The real main.py startup path is covered by the manual "Check D" run.)
"""
import json
import os
import shlex
import signal
import sqlite3
import subprocess
import sys
import time

import psutil
import pytest

import config
from core import logger
from core.state import NORMAL
from dashboard.app import create_app
from database import db_manager
from generate_samples import generate
from main import RewindApp
from tools.show_log import format_record
from tools.verify_restore import verify

ATTACKS = os.path.join(config.BASE_DIR, "test_ransomware")
SETTLE_SECONDS = 1.6
INCIDENT_TIMEOUT = 30
HOLD_CODE = ("import sys, time\n"
             "f = open(sys.argv[1], 'rb')\n"
             "print('ready', flush=True)\n"
             "time.sleep(300)\n")


def wait_for(predicate, timeout, interval=0.2):
    deadline = time.time() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.time() >= deadline:
            return None
        time.sleep(interval)


def csv(value):
    return [part for part in (value or "").split(",") if part]


def alive(pid):
    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def records(paths):
    found = []
    try:
        with open(paths["log_path"], encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    found.append(rec)
    except OSError:
        pass
    return found


def incidents(paths):
    try:
        return db_manager.get_all_incidents(paths["db_path"])
    except sqlite3.Error:
        return []


def wait_for_incident(paths, timeout=INCIDENT_TIMEOUT):
    return wait_for(lambda: incidents(paths), timeout, 0.25) or []


def response_finished(app, timeout=30):
    return wait_for(lambda: app.pipeline.incidents_handled >= 1, timeout, 0.25)


def files_intact(paths):
    matched, total, _problems, _extras = verify(paths["protected_dir"], paths["hashes_path"])
    return total > 0 and matched == total


def explain(paths, note):
    recent = "\n".join(format_record(r) for r in records(paths)[-25:])
    return "%s\n--- last Rewind log lines ---\n%s" % (note, recent)


@pytest.fixture
def paths(tmp_path):
    p = dict(protected_dir=str(tmp_path / "protected"), safety_dir=str(tmp_path / "safety"),
             hashes_path=str(tmp_path / "data" / "hashes.json"),
             db_path=str(tmp_path / "rewind.db"), log_path=str(tmp_path / "rewind.log"))
    generate(**p)
    logger.set_log_path(p["log_path"])
    return p


@pytest.fixture
def rewind(paths):
    started = []

    def start(attribute=True, snapshot_interval=None):
        app = RewindApp(protected_dir=paths["protected_dir"], safety_dir=paths["safety_dir"],
                        db_path=paths["db_path"], say=lambda message: None)
        app.watcher.attribute = attribute
        started.append(app)
        app.start(periodic=False)
        if snapshot_interval:
            app.snapshots.start_periodic(interval=snapshot_interval)
        time.sleep(SETTLE_SECONDS)
        return app

    yield start
    for app in started:
        app.stop()


class Attackers:
    def __init__(self, target):
        self.target = target
        self.procs = []
        self.pids = []

    def launch(self, script, *args):
        proc = subprocess.Popen(
            [sys.executable, os.path.join(ATTACKS, script), "--target", self.target, *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(proc)
        return proc

    def launch_detached(self, script, *args):
        argv = [sys.executable, os.path.join(ATTACKS, script), "--target", self.target, *args]
        # `setsid -f` always forks, so the attacker really gets its own session. Because the
        # PID that setsid itself prints would be the short-lived parent, the inner shell
        # writes ITS OWN pid ($$) to a file; `exec` keeps that pid for the attacker.
        pidfile = os.path.join(os.path.dirname(self.target), "s2_attacker.pid")   # outside the sandbox
        inner = "echo $$ > %s; sleep 1.5; exec %s" % (shlex.quote(pidfile), shlex.join(argv))
        subprocess.run(["setsid", "-f", "sh", "-c", inner], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)

        def read_pid():
            try:
                with open(pidfile, encoding="utf-8") as f:
                    return int(f.read().strip())
            except (OSError, ValueError):
                return None

        pid = wait_for(read_pid, 5)
        assert pid, "the detached attacker never reported its PID (is setsid installed?)"
        self.pids.append(pid)
        return pid

    def track_pid(self, pid):
        self.pids.append(pid)

    def cleanup(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        for pid in self.pids:
            try:
                psutil.Process(pid).kill()
            except psutil.Error:
                pass


@pytest.fixture
def attackers(paths):
    group = Attackers(paths["protected_dir"])
    yield group
    group.cleanup()


def test_s1_live_dashboard_simulate_button_stops_a_real_attack(paths, rewind, attackers,
                                                               monkeypatch):
    app = rewind()
    monkeypatch.setenv("REWIND_ALLOW_SIMULATE", "1")
    dash = create_app(protected_dir=paths["protected_dir"], db_path=paths["db_path"],
                      log_path=paths["log_path"]).test_client()
    status = dash.get("/api/status").get_json()
    assert status["simulate_enabled"] is True and status["sandbox_ok"] is True
    assert status["engine_running"] is True, explain(paths, "dashboard thinks Rewind is offline")
    reply = dash.post("/api/simulate", json={"variant": "v1", "avoid_decoys": False})
    body = reply.get_json()
    assert reply.status_code == 200 and body["ok"] is True, \
        explain(paths, "Simulate was refused: %r" % body)
    attackers.track_pid(body["pid"])
    rows = wait_for_incident(paths)
    assert rows, explain(paths, "no incident within %d s" % INCIDENT_TIMEOUT)
    row = rows[0]
    assert "DECOY" in csv(row["signals"])
    assert row["status"] == "RESOLVED" and row["verified"] == 1
    assert str(body["pid"]) in csv(row["killed_pids"]), "the simulated attacker was not the one killed"
    listed = dash.get("/api/incidents").get_json()
    assert listed and listed[0]["id"] == row["id"]
    assert listed[0]["status"] == "RESOLVED" and listed[0]["verified"] is True
    assert "DECOY" in listed[0]["signals"]
    assert dash.get("/api/status").get_json()["last_incident"]["id"] == row["id"]
    assert response_finished(app), explain(paths, "the response never finished")
    page = dash.get("/incidents/%d" % row["id"])
    assert page.status_code == 200 and "Integrity check passed" in page.get_data(as_text=True)
    assert files_intact(paths), explain(paths, "files were not restored 100/100")


def test_s2_attacker_started_outside_rewinds_process_family(paths, rewind, attackers):
    app = rewind()
    pid = attackers.launch_detached("ransomware_v1.py")
    try:
        parent = psutil.Process(pid).ppid()
    except psutil.NoSuchProcess:
        pytest.fail(explain(paths, "the detached attacker died before it could be inspected"))
    assert parent != os.getpid(), "the attacker is Rewind's own child"
    assert os.getsid(pid) != os.getsid(0), "the attacker shares Rewind's session"
    rows = wait_for_incident(paths)
    assert rows, explain(paths, "no incident within %d s" % INCIDENT_TIMEOUT)
    row = rows[0]
    assert wait_for(lambda: not alive(pid), 15), "the attacker is still running"
    assert "DECOY" in csv(row["signals"])
    assert row["status"] == "RESOLVED" and row["verified"] == 1
    assert str(pid) in csv(row["killed_pids"]), explain(paths, "the wrong process was killed")
    assert response_finished(app), explain(paths, "the response never finished")
    assert files_intact(paths), explain(paths, "files were not restored 100/100")
    assert len(incidents(paths)) == 1


def test_s3a_strong_xor_is_caught_by_speed_and_entropy(paths, rewind, attackers):
    app = rewind()
    attacker = attackers.launch("ransomware_v2.py", "--avoid-decoys")
    rows = wait_for_incident(paths)
    assert rows, explain(paths, "no incident within %d s" % INCIDENT_TIMEOUT)
    row = rows[0]
    assert attacker.wait(timeout=15) == -signal.SIGKILL
    signals = csv(row["signals"])
    assert "SPEED" in signals and "ENTROPY" in signals
    assert "DECOY" not in signals
    assert row["status"] == "RESOLVED" and row["verified"] == 1
    assert str(attacker.pid) in csv(row["killed_pids"])
    assert len(csv(row["restored_files"])) >= 20, explain(paths, "too few files restored")
    assert response_finished(app), explain(paths, "the response never finished")
    assert files_intact(paths), explain(paths, "files were not restored 100/100")


def test_s3b_weak_xor_is_caught_by_the_sustained_rule(paths, rewind, attackers):
    app = rewind()
    attacker = attackers.launch("ransomware_v2.py", "--weak", "--avoid-decoys")
    rows = wait_for_incident(paths)
    assert rows, explain(paths, "no incident within %d s" % INCIDENT_TIMEOUT)
    row = rows[0]
    assert attacker.wait(timeout=15) == -signal.SIGKILL
    recs = records(paths)
    suspicious = [r["ts"] for r in recs if r["action"] == "verdict_suspicious"]
    confirmed = [r for r in recs if r["action"] == "verdict_confirmed"]
    assert suspicious and confirmed, explain(paths, "expected SUSPICIOUS and then CONFIRMED")
    assert min(suspicious) < confirmed[0]["ts"]
    assert confirmed[0]["ts"] - min(suspicious) >= 2.0
    assert "SPEED" in confirmed[0]["signals"] and "SUSTAINED" in confirmed[0]["signals"]
    assert "ENTROPY" not in confirmed[0]["signals"]
    assert "SUSTAINED" in csv(row["signals"]) and "ENTROPY" not in csv(row["signals"])
    assert row["status"] == "RESOLVED" and row["verified"] == 1
    assert response_finished(app), explain(paths, "the response never finished")
    assert files_intact(paths), explain(paths, "files were not restored 100/100")


def test_s5_restore_does_not_set_off_a_second_alarm(paths, rewind, attackers):
    app = rewind()
    attacker = attackers.launch("ransomware_v1.py")
    rows = wait_for_incident(paths)
    assert rows, explain(paths, "no incident within %d s" % INCIDENT_TIMEOUT)
    assert attacker.wait(timeout=15) == -signal.SIGKILL
    assert response_finished(app), explain(paths, "the response never finished")
    time.sleep(8)
    recs = records(paths)
    done = [r["ts"] for r in recs if r["action"] == "restore_done"]
    assert done, explain(paths, "the restore never finished")
    late = [r["action"] for r in recs if r["ts"] > max(done)
            and r["action"] in ("verdict_suspicious", "verdict_confirmed", "response_start")]
    assert late == [], explain(paths, "alarms after the restore: %s" % late)
    assert sum(1 for r in recs if r["action"] == "response_start") == 1
    assert sum(1 for r in recs if r["action"] == "verdict_confirmed") == 1
    assert len(incidents(paths)) == 1
    assert rows[0]["status"] == "RESOLVED" and rows[0]["verified"] == 1
    assert files_intact(paths) and app.state.state == NORMAL


def test_s3d_a_real_tar_archive_raises_no_alarm(paths, rewind):
    app = rewind()
    sandbox = paths["protected_dir"]
    result = subprocess.run("tar czf backup.tgz document_*.txt", shell=True, cwd=sandbox,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    time.sleep(4)
    archive = os.path.join(sandbox, "backup.tgz")
    assert os.path.isfile(archive) and os.path.getsize(archive) > 1000
    assert incidents(paths) == []
    alarms = {r["action"] for r in records(paths)} & {
        "verdict_suspicious", "verdict_confirmed", "response_start", "kill_tree"}
    assert not alarms, explain(paths, "unexpected alarm activity: %s" % sorted(alarms))
    assert app.state.state == NORMAL


def test_s3e_legitimate_edits_become_trusted_only_after_ten_quiet_seconds(paths, rewind):
    app = rewind()
    sandbox, safety = paths["protected_dir"], paths["safety_dir"]
    edited = ["document_003.txt", "document_004.txt", "document_005.txt"]

    def pending(name):
        return os.path.isfile(os.path.join(safety, "live_pending", name))

    def trusted(name):
        return os.path.isfile(os.path.join(safety, "live", name))

    for name in edited:
        with open(os.path.join(sandbox, name), "a", encoding="utf-8") as f:
            f.write("A legitimate edit typed by a person.\n")
    t_last_edit = time.time()
    assert wait_for(lambda: all(pending(n) for n in edited), 8), \
        explain(paths, "the edited files never became pending known-good copies")
    assert not any(trusted(n) for n in edited)
    time.sleep(max(0.0, 10.7 - (time.time() - t_last_edit)))
    assert not any(trusted(n) for n in edited), \
        explain(paths, "time alone promoted a copy (promotion should be event-driven)")
    with open(os.path.join(sandbox, "document_006.txt"), "a", encoding="utf-8") as f:
        f.write("One more legitimate edit.\n")
    assert wait_for(lambda: all(trusted(n) for n in edited), 10), \
        explain(paths, "the aged copies were not promoted by the next clean event")
    for name in edited:
        with open(os.path.join(sandbox, name), "rb") as a, \
                open(os.path.join(safety, "live", name), "rb") as b:
            assert a.read() == b.read()
    assert pending("document_006.txt") and not trusted("document_006.txt")
    assert incidents(paths) == []
    assert not ({r["action"] for r in records(paths)}
                & {"verdict_suspicious", "verdict_confirmed", "response_start"})


def test_s4_snapshot_timer_firing_mid_attack_never_captures_damage(paths, rewind, attackers):
    app = rewind(snapshot_interval=1)
    attacker = attackers.launch("ransomware_v1.py", "--avoid-decoys", "--rate", "10")
    rows = wait_for_incident(paths)
    assert rows, explain(paths, "no incident within %d s" % INCIDENT_TIMEOUT)
    row = rows[0]
    assert attacker.wait(timeout=15) == -signal.SIGKILL
    assert response_finished(app), explain(paths, "the response never finished")
    time.sleep(3)
    recs = records(paths)
    alerts = [r["ts"] for r in recs if r["action"] in ("verdict_suspicious", "verdict_confirmed")]
    ends = [r["ts"] for r in recs if r["action"] == "response_end"]
    assert alerts and ends, explain(paths, "no alert or response_end was logged")
    start, end = min(alerts), max(ends)
    window = [r for r in recs if start < r["ts"] < end + 8]
    taken = [r for r in window if r["action"] == "snapshot_taken"]
    held_back = [r for r in window if r["action"] in ("snapshot_skipped", "snapshot_discarded")]
    assert taken == [], explain(paths, "a snapshot was kept during the attack: %s" % taken)
    assert held_back, explain(paths, "the snapshot timer never fired during the attack")
    for name in sorted(os.listdir(paths["safety_dir"])):
        snap = os.path.join(paths["safety_dir"], name)
        if not name.startswith("snapshot_") or name.endswith(".tmp"):
            continue
        try:
            with open(os.path.join(snap, "manifest.json"), encoding="utf-8") as f:
                files = json.load(f)["files"]
        except (OSError, ValueError, KeyError):
            continue
        noisy = sorted(n for n, e in files.items()
                       if n.startswith("document_") and e.get("entropy", 0) >= 7.5)
        assert noisy == [], "snapshot %s contains scrambled files: %s" % (name, noisy[:3])
    assert "ENTROPY" in csv(row["signals"])
    assert row["status"] == "RESOLVED" and row["verified"] == 1
    assert files_intact(paths), explain(paths, "files were not restored 100/100")


def test_s6_unidentified_attacker_means_nobody_is_killed(paths, rewind, attackers):
    app = rewind(attribute=False)
    holders = []
    try:
        for i in range(4):
            path = os.path.join(paths["protected_dir"], "document_%03d.txt" % (90 + i))
            holder = subprocess.Popen([sys.executable, "-c", HOLD_CODE, path],
                                      stdout=subprocess.PIPE, text=True)
            holders.append(holder)
            assert holder.stdout.readline().strip() == "ready"
        attacker = attackers.launch("ransomware_v1.py")
        rows = wait_for_incident(paths, timeout=45)
        assert rows, explain(paths, "no incident within 45 s")
        row = rows[0]
        assert attacker.wait(timeout=30) == 0
        assert row["status"] == "UNATTRIBUTED_ALERT"
        assert csv(row["killed_pids"]) == []
        assert [h.poll() for h in holders] == [None] * 4, "an innocent process was killed"
        sweep = json.loads(row["details"])["response"]["sweep"]
        assert sweep["ambiguous"] is True and len(sweep["candidates"]) > 3
        assert not [r for r in records(paths) if r["action"] == "kill_tree"]
        assert row["verified"] == 1
        assert response_finished(app, timeout=30), explain(paths, "the response never finished")
        assert files_intact(paths), explain(paths, "files were not restored 100/100")
    finally:
        for holder in holders:
            if holder.poll() is None:
                holder.kill()
            holder.wait(timeout=5)