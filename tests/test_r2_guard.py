"""Rule R2 as a runtime invariant: respond_to_attack() only acts on a CONFIRMED verdict.

Any other level raises RuntimeError and logs the rejection BEFORE anything is touched:
no kill, no restore, no incident row, no state change. The pipeline catches the refusal
and carries on.
"""
import json
import time

import pytest

from core import logger
from core.activity import ActivityMonitor
from core.events import CLEAN, CONFIRMED, SUSPICIOUS, FileEvent, Verdict
from core.pipeline import Pipeline
from core.state import NORMAL, ThreatState
from detection.decoy_monitor import DecoyMonitor
from recovery.known_good import KnownGoodTracker
from recovery.manifest import Manifest, build_manifest
from recovery.restore_engine import RestoreResult
from response.response_engine import KillReport, SweepResult, respond_to_attack


class Spies:
    """Records every side effect, so a test can prove that NOTHING happened."""

    def __init__(self):
        self.kills, self.sweeps, self.restores, self.logged = [], [], [], []

    def kill(self, pid):
        self.kills.append(pid)
        return KillReport(killed=[pid], failed=[])

    def sweep(self, folder):
        self.sweeps.append(folder)
        return SweepResult([], False, [], "none")

    def restore(self):
        self.restores.append(1)
        return RestoreResult(restored=["a.txt"], verified=True, snapshot_used="snapshot_1")

    def restore_impl(self, *args, **kwargs):          # the pipeline's restore hook
        self.restores.append(1)
        return RestoreResult(verified=True)

    def log(self, **fields):                          # stands in for the incident database
        self.logged.append(fields)
        return 1

    def nothing_happened(self):
        return not (self.kills or self.sweeps or self.restores or self.logged)


def call(verdict, spies, state, pid=1234):
    return respond_to_attack(verdict, pid, spies.restore, spies.log, state,
                             activity=ActivityMonitor(), kill_fn=spies.kill,
                             sweep_fn=spies.sweep, sleep_fn=lambda s: None, trace_id="r2test")


def logged_records():
    try:
        with open(logger.get_log_path(), encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []


def test_respond_to_attack_rejects_clean_verdict():
    spies, state = Spies(), ThreatState()
    before = state.generation
    with pytest.raises(RuntimeError, match="only CONFIRMED"):
        call(Verdict(CLEAN, [], {}), spies, state)
    assert spies.nothing_happened()                         # no kill, sweep, restore or incident row
    assert state.state == NORMAL and state.generation == before    # no state change either
    rejected = [r for r in logged_records() if r["action"] == "response_rejected"]
    assert len(rejected) == 1                               # the refusal itself was logged
    assert rejected[0]["level"] == "CLEAN" and rejected[0]["reason"] == "not CONFIRMED"
    assert rejected[0]["incident_trace_id"] == "r2test" and rejected[0]["pid"] == 1234


def test_respond_to_attack_rejects_suspicious_verdict():
    spies, state = Spies(), ThreatState()
    before = state.generation
    with pytest.raises(RuntimeError, match="only CONFIRMED"):
        call(Verdict(SUSPICIOUS, ["SPEED"], {"note": "one signal only"}), spies, state)
    assert spies.nothing_happened()
    assert state.state == NORMAL and state.generation == before
    rejected = [r for r in logged_records() if r["action"] == "response_rejected"]
    assert len(rejected) == 1
    assert rejected[0]["level"] == "SUSPICIOUS" and rejected[0]["signals"] == ["SPEED"]


def test_respond_to_attack_accepts_confirmed_verdict():
    spies, state = Spies(), ThreatState()
    with pytest.raises(RuntimeError):
        call(Verdict(CLEAN, [], {}), spies, state)          # a refusal must not jam anything ...
    out = call(Verdict(CONFIRMED, ["DECOY"], {"why": "test"}), spies, state)   # ... so this works
    assert out is not None and out.status == "RESOLVED"
    assert spies.kills == [1234] and len(spies.restores) == 1 and len(spies.logged) == 1
    assert spies.logged[0]["signals"] == ["DECOY"] and spies.logged[0]["pid"] == 1234
    assert spies.logged[0]["details"]["why"] == "test"      # the verdict's details reach the incident
    assert state.state == NORMAL
    rejected = [r for r in logged_records() if r["action"] == "response_rejected"]
    assert len(rejected) == 1                               # only the earlier CLEAN attempt


def test_pipeline_does_not_crash_on_r2_violation(tmp_path):
    folder = tmp_path / "protected"
    folder.mkdir()
    for i in range(3):
        (folder / ("document_%03d.txt" % i)).write_text("some plain text " * 50)
    decoys = DecoyMonitor(str(folder))
    decoy_paths = decoys.plant_decoys()
    manifest = Manifest(root=str(folder), data=build_manifest(str(folder)))
    spies = Spies()

    def sabotaged(verdict, pid, restore_fn, log_fn, state, **kwargs):
        # Simulates a bug upstream: the REAL response engine is handed a non-CONFIRMED verdict.
        return respond_to_attack(Verdict(CLEAN, verdict.signals, verdict.details), pid,
                                 restore_fn, log_fn, state, **kwargs)

    pipe = Pipeline(manifest=manifest, decoys=decoys,
                    known_good=KnownGoodTracker(str(folder), str(tmp_path / "safety")),
                    protected_dir=str(folder), safety_dir=str(tmp_path / "safety"),
                    respond_fn=sabotaged, restore_impl=spies.restore_impl,
                    log_incident_fn=spies.log, async_response=False)
    for n in range(2):                                      # twice: the pipeline must stay usable
        event = FileEvent(path=decoy_paths[n], event_type="modified",
                          timestamp=time.time() + n, pid=4242)
        verdict = pipe.handle_event(event)                  # must NOT raise
        assert verdict.level == CONFIRMED                   # detection still judged correctly
        assert pipe.state.state == NORMAL                   # and the pipeline did not get stuck
    assert spies.restores == [] and spies.logged == []      # nothing was restored or recorded
    actions = [r["action"] for r in logged_records()]
    assert actions.count("response_rejected") == 2
    assert actions.count("pipeline_response_guard_caught") == 2
