import functools
import os
import random
import time
from types import SimpleNamespace

import config
from core.events import CLEAN, CONFIRMED, SUSPICIOUS, FileEvent
from core.pipeline import Pipeline
from core.state import ELEVATED, NORMAL, RESPONDING, ThreatState
from database import db_manager
from detection.decoy_monitor import DecoyMonitor
from generate_samples import make_document_text
from recovery.known_good import KnownGoodTracker
from recovery.manifest import Manifest, build_manifest, sha256_file
from recovery.restore_engine import RestoreResult
from recovery.snapshot_manager import SnapshotManager
from response.response_engine import KillReport, SweepResult, respond_to_attack
from watcher.watcher_control import WatcherControl

T0 = 50000.0


class FakeResponder:
    """Stands in for the response engine so we can test the pipeline's decisions exactly."""

    def __init__(self, status="RESOLVED"):
        self.calls = []
        self.status = status
        self.during = None
        self.run_restore = False
        self.raise_error = False

    def __call__(self, pid, signals, details, restore_fn, log_fn, state, **kwargs):
        self.calls.append(SimpleNamespace(pid=pid, signals=list(signals), details=details,
                                          trace_id=kwargs.get("trace_id"),
                                          state_during=state.state))
        if self.raise_error:
            raise RuntimeError("boom")
        if self.during:
            self.during()
        if self.run_restore:
            restore_fn()
        return SimpleNamespace(status=self.status)


def ev(path, t, pid=100, kind="modified"):
    return FileEvent(path=str(path), event_type=kind, timestamp=t, pid=pid)


def make_files(tmp_path, n=100):
    folder = tmp_path / "protected"
    folder.mkdir()
    rng = random.Random(5)
    for i in range(n):
        (folder / ("document_%03d.txt" % i)).write_bytes(
            make_document_text(i, rng).encode("utf-8"))
    decoys = DecoyMonitor(str(folder))
    decoy_paths = decoys.plant_decoys()
    manifest = Manifest(root=str(folder), data=build_manifest(str(folder)))
    return folder, tmp_path / "safety", decoys, decoy_paths, manifest


def build(tmp_path, responder=None, n=100, **kw):
    folder, safety, decoys, decoy_paths, manifest = make_files(tmp_path, n)
    known_good = KnownGoodTracker(str(folder), str(safety))
    responder = responder or FakeResponder()
    restore_calls = []

    def restore_spy(attack_start, **kwargs):
        restore_calls.append(attack_start)
        return RestoreResult(verified=True)

    pipe = Pipeline(manifest=manifest, decoys=decoys, known_good=known_good,
                    protected_dir=str(folder), safety_dir=str(safety), respond_fn=responder,
                    restore_impl=restore_spy, log_incident_fn=lambda **fields: 1,
                    async_response=False, **kw)
    return SimpleNamespace(folder=folder, safety=safety, pipe=pipe, responder=responder,
                           restore_calls=restore_calls, decoys=decoy_paths, manifest=manifest)


def doc(w, i):
    return w.folder / ("document_%03d.txt" % i)


def encrypt_and_report(w, count, pid=4242, start=T0, step=0.05):
    levels = []
    for i in range(count):
        doc(w, i).write_bytes(os.urandom(8192))
        verdict = w.pipe.handle_event(ev(doc(w, i), start + i * step, pid=pid))
        levels.append(verdict.level)
    return levels


def test_a_normal_edit_is_judged_clean_and_saved_as_known_good(tmp_path):
    w = build(tmp_path)
    p = doc(w, 0)
    p.write_bytes(p.read_bytes() + b"my edit\n")
    verdict = w.pipe.handle_event(ev(p, T0))
    assert verdict.level == CLEAN
    assert (w.safety / "live" / "document_000.txt").read_bytes() == p.read_bytes()
    assert w.responder.calls == []


def test_a_brand_new_noisy_file_never_raises_an_alarm(tmp_path):
    w = build(tmp_path, n=5)
    z = w.folder / "backup.zip"
    for i in range(60):
        z.write_bytes(os.urandom(8192 + i))
        verdict = w.pipe.handle_event(ev(z, T0 + i * 0.02, kind="created" if i == 0 else "modified"))
        assert verdict.level == CLEAN
    assert not (w.safety / "live" / "backup.zip").exists()
    assert w.pipe.state.state == NORMAL and w.responder.calls == []


def test_touching_a_decoy_triggers_exactly_one_response(tmp_path):
    w = build(tmp_path)
    verdict = w.pipe.handle_event(ev(w.decoys[0], T0, pid=4242))
    assert verdict.level == CONFIRMED
    assert len(w.responder.calls) == 1
    call = w.responder.calls[0]
    assert call.pid == 4242 and call.signals == ["DECOY"] and call.state_during == RESPONDING
    assert w.pipe.state.state == NORMAL


def test_rewinds_own_activity_is_ignored(tmp_path):
    w = build(tmp_path)
    assert w.pipe.handle_event(ev(w.decoys[0], T0, pid=os.getpid())) is None
    assert w.responder.calls == [] and w.pipe.events_dropped == 1


def test_events_while_paused_or_from_before_the_resume_are_ignored(tmp_path):
    control = WatcherControl()
    w = build(tmp_path, control=control)
    with control.paused():
        assert w.pipe.handle_event(ev(w.decoys[0], time.time() + 5, pid=4242)) is None
    assert w.pipe.handle_event(ev(w.decoys[0], T0, pid=4242)) is None          # older than the resume
    assert w.responder.calls == []
    assert w.pipe.handle_event(ev(w.decoys[0], time.time() + 5, pid=4242)).level == CONFIRMED
    assert len(w.responder.calls) == 1


def test_events_during_a_response_cannot_start_a_second_one(tmp_path):
    w = build(tmp_path)
    w.responder.during = lambda: w.pipe.handle_event(ev(w.decoys[1], T0 + 0.1, pid=4242))
    w.pipe.handle_event(ev(w.decoys[0], T0, pid=4242))
    assert len(w.responder.calls) == 1


def test_speed_plus_entropy_confirms_and_passes_the_attacker_pid(tmp_path):
    w = build(tmp_path)
    levels = encrypt_and_report(w, 30)
    assert levels[:24] == [SUSPICIOUS] * 24
    assert levels[24] == CONFIRMED
    assert len(w.responder.calls) == 1
    call = w.responder.calls[0]
    assert call.pid == 4242 and call.signals == ["SPEED", "ENTROPY"]


def test_a_slow_one_signal_attack_escalates_to_sustained(tmp_path):
    w = build(tmp_path)
    for i in range(100):                  # files are not really changed: SPEED only
        w.pipe.handle_event(ev(doc(w, i), T0 + i * 0.05))
    assert len(w.responder.calls) == 1
    assert w.responder.calls[0].signals == ["SPEED", "SUSTAINED"]


def test_restore_is_told_the_attack_started_at_the_first_alert(tmp_path):
    w = build(tmp_path)
    w.responder.run_restore = True
    encrypt_and_report(w, 30)
    assert w.restore_calls == [T0]


def test_suspicion_fades_back_to_normal_after_a_calm_period(tmp_path):
    w = build(tmp_path)
    doc(w, 0).write_bytes(os.urandom(8192))
    assert w.pipe.handle_event(ev(doc(w, 0), T0)).level == SUSPICIOUS
    assert w.pipe.state.state == ELEVATED
    w.pipe.tick(T0 + 4.9)
    assert w.pipe.state.state == ELEVATED
    w.pipe.tick(T0 + 5.1)
    assert w.pipe.state.state == NORMAL


def test_the_counters_start_fresh_after_a_response(tmp_path):
    w = build(tmp_path)
    for i in range(10):
        w.pipe.handle_event(ev(doc(w, i), T0 + i * 0.01))
    assert w.pipe.speed.count(config.FOLDER_WIDE_ACTOR, now=T0 + 0.2) == 10
    w.pipe.handle_event(ev(w.decoys[0], T0 + 0.2, pid=4242))
    assert w.pipe.speed.count(config.FOLDER_WIDE_ACTOR, now=T0 + 0.3) == 0


def test_after_a_still_active_outcome_detection_keeps_working(tmp_path):
    w = build(tmp_path, responder=FakeResponder(status="STILL_ACTIVE"))
    w.pipe.handle_event(ev(w.decoys[0], T0, pid=4242))
    assert w.pipe.state.state == NORMAL
    w.pipe.handle_event(ev(w.decoys[1], T0 + 1, pid=4242))
    assert len(w.responder.calls) == 2


def test_a_crashing_response_does_not_break_the_pipeline(tmp_path):
    responder = FakeResponder()
    responder.raise_error = True
    w = build(tmp_path, responder=responder)
    w.pipe.handle_event(ev(w.decoys[0], T0, pid=4242))
    assert w.pipe.state.state == NORMAL
    responder.raise_error = False
    w.pipe.handle_event(ev(w.decoys[1], T0 + 1, pid=4242))
    assert len(responder.calls) == 2 and w.pipe.incidents_handled == 2


def test_status_reports_state_and_counters(tmp_path):
    w = build(tmp_path)
    w.pipe.handle_event(ev(doc(w, 0), T0))
    w.pipe.handle_event(ev(doc(w, 1), T0, pid=os.getpid()))
    status = w.pipe.status()
    assert status["state"] == NORMAL and status["events_seen"] == 2
    assert status["events_dropped"] == 1 and status["protected_files"] == 103


def test_full_chain_with_the_real_response_and_restore_engines(tmp_path):
    folder, safety, decoys, decoy_paths, manifest = make_files(tmp_path)
    known_good = KnownGoodTracker(str(folder), str(safety))
    state = ThreatState()
    originals = {p.name: sha256_file(str(p)) for p in folder.glob("document_*.txt")}
    snaps = SnapshotManager(state, manifest=manifest, known_good=known_good,
                            protected_dir=str(folder), safety_dir=str(safety),
                            clock=lambda: time.time() - 100)
    assert snaps.take_snapshot() is not None
    for i in range(5):                                   # the attacker damages 5 files
        doc(SimpleNamespace(folder=folder), i).write_bytes(os.urandom(8192))
    db = str(tmp_path / "t.db")
    responder = functools.partial(
        respond_to_attack,
        kill_fn=lambda pid: KillReport(killed=[pid], failed=[]),
        sweep_fn=lambda f: SweepResult([], False, [], "none"),
        sleep_fn=lambda s: None)
    pipe = Pipeline(manifest=manifest, decoys=decoys, known_good=known_good,
                    protected_dir=str(folder), safety_dir=str(safety), state=state,
                    control=WatcherControl(), respond_fn=responder,
                    log_incident_fn=functools.partial(db_manager.log_incident, db_path=db),
                    async_response=False)
    verdict = pipe.handle_event(FileEvent(path=decoy_paths[0], event_type="modified",
                                          timestamp=time.time() - 10, pid=4242))
    assert verdict.level == CONFIRMED
    for name, digest in originals.items():
        assert sha256_file(str(folder / name)) == digest
    rows = db_manager.get_all_incidents(db)
    assert len(rows) == 1
    assert rows[0]["status"] == "RESOLVED" and rows[0]["verified"] == 1
    assert rows[0]["attacker_pid"] == 4242 and rows[0]["signals"] == "DECOY"
    assert rows[0]["killed_pids"] == "4242"
    assert state.state == NORMAL
