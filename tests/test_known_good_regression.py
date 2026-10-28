"""Regression tests for the known_good trust hole (written BEFORE the fix).

THE HOLE: while an attacker's writes still look harmless (CLEAN verdicts), the pipeline
saves each damaged file as a "last known good" copy. At restore time those copies
override the clean snapshot, so the damage is restored as if it were legitimate, and the
restore even reports "verified". These tests do the damage inline (no real attacker
process); the real wiper and ransomware_v2 scripts are built later.

Time is simulated: events carry timestamps, and pipe.tick(t) moves the clock forward.
"""
import functools
import random
import time
from types import SimpleNamespace

import pytest

from core.events import CLEAN, CONFIRMED, FileEvent
from core.pipeline import Pipeline
from core.state import ThreatState
from database import db_manager
from detection.decoy_monitor import DecoyMonitor
from detection.entropy_checker import calculate_entropy_bytes
from generate_samples import make_document_text
from recovery.known_good import KnownGoodTracker
from recovery.manifest import Manifest, build_manifest
from recovery.snapshot_manager import SnapshotManager
from response.response_engine import KillReport, SweepResult, respond_to_attack
from watcher.watcher_control import WatcherControl

WEAK_KEY = bytes([0x5A, 0xC3, 0x17, 0x9E])      # the 4-byte repeating key of "--weak"


def weak_xor(data):
    return bytes(b ^ WEAK_KEY[i % 4] for i, b in enumerate(data))


DAMAGE = {"zero_fill": lambda data: bytes(len(data)), "weak_xor": weak_xor}


def build_world(tmp_path):
    """100 sample files + decoys + a clean snapshot, plus the real pipeline, response and restore."""
    folder = tmp_path / "protected"
    folder.mkdir()
    rng = random.Random(11)
    originals = {}
    for i in range(100):
        name = "document_%03d.txt" % i
        data = make_document_text(i, rng).encode("utf-8")
        (folder / name).write_bytes(data)
        originals[name] = data
    decoys = DecoyMonitor(str(folder))
    decoy_paths = decoys.plant_decoys()
    safety = tmp_path / "safety"
    manifest = Manifest(root=str(folder), data=build_manifest(str(folder)))
    known_good = KnownGoodTracker(str(folder), str(safety))
    state = ThreatState()
    base = time.time() - 300                      # the whole story happens "5 minutes ago"
    snaps = SnapshotManager(state, manifest=manifest, known_good=known_good,
                            protected_dir=str(folder), safety_dir=str(safety),
                            clock=lambda: base - 100)
    assert snaps.take_snapshot() is not None
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
    return SimpleNamespace(folder=folder, originals=originals, decoys=decoy_paths,
                           base=base, pipe=pipe, db=db)


def event(path, t, pid=4242):
    return FileEvent(path=str(path), event_type="modified", timestamp=t, pid=pid)


def damage(w, name, kind):
    path = w.folder / name
    path.write_bytes(DAMAGE[kind](w.originals[name]))
    return path


def wrong_files(w):
    """Names of files whose content is not the original any more."""
    return sorted(n for n, data in w.originals.items()
                  if (w.folder / n).read_bytes() != data)


def decoy_attack(w, t):
    """A separate, obvious attack (touching a decoy) that triggers a restore."""
    verdict = w.pipe.handle_event(event(w.decoys[0], t, pid=777))
    assert verdict.level == CONFIRMED
    return verdict


# ---------------------------------------------------------------- sanity (passes today)
def test_the_weak_xor_variant_really_stays_below_the_entropy_alarm():
    rng = random.Random(1)
    for i in range(5):
        original = make_document_text(i, rng).encode("utf-8")
        scrambled = weak_xor(original)
        assert scrambled != original
        assert calculate_entropy_bytes(scrambled) < 7.5


# ---------------------------------------------------------------- the hole (FAIL today)
@pytest.mark.parametrize("kind", ["zero_fill", "weak_xor"])
def test_a_fast_wiper_cannot_poison_the_restore(tmp_path, kind):
    w = build_world(tmp_path)
    confirmed = False
    for i in range(100):                          # about 20 files per second
        path = damage(w, "document_%03d.txt" % i, kind)
        verdict = w.pipe.handle_event(event(path, w.base + i * 0.05))
        if verdict.level == CONFIRMED:
            confirmed = True
            break
    assert confirmed, "the fast attack was never confirmed"
    assert len(db_manager.get_all_incidents(w.db)) == 1
    bad = wrong_files(w)
    assert bad == [], "%d files were NOT restored correctly, e.g. %s" % (len(bad), bad[:3])


@pytest.mark.parametrize("kind", ["zero_fill", "weak_xor"])
def test_a_slow_wiper_cannot_poison_the_restore(tmp_path, kind):
    w = build_world(tmp_path)
    for i in range(5):                            # 1 file every 3 seconds
        path = damage(w, "document_%03d.txt" % i, kind)
        verdict = w.pipe.handle_event(event(path, w.base + i * 3.0))
        assert verdict.level == CLEAN             # side effect (b): the wiper is NOT detected
    w.pipe.tick(w.base + 19.0)                    # time passes ...
    decoy_attack(w, w.base + 20.0)                # ... then some other attack is confirmed
    bad = wrong_files(w)
    assert bad == [], "%d files were NOT restored correctly, e.g. %s" % (len(bad), bad[:3])


# ---------------------------------------------------------------- must keep working
def test_a_legitimate_edit_made_well_before_an_attack_survives(tmp_path):
    w = build_world(tmp_path)
    name = "document_003.txt"
    edited = w.originals[name] + b"A legitimate edit by a person.\n"
    (w.folder / name).write_bytes(edited)
    assert w.pipe.handle_event(event(w.folder / name, w.base)).level == CLEAN
    w.pipe.tick(w.base + 6.0)
    w.pipe.tick(w.base + 12.0)                    # more than 10 s without any alert
    decoy_attack(w, w.base + 20.0)
    assert (w.folder / name).read_bytes() == edited
    assert [n for n in wrong_files(w) if n != name] == []


# ---------------------------------------------------------------- side effect (a)
def test_an_edit_made_seconds_before_an_attack_is_lost_by_design(tmp_path):
    w = build_world(tmp_path)
    name = "document_003.txt"
    edited = w.originals[name] + b"A last-second legitimate edit.\n"
    (w.folder / name).write_bytes(edited)
    assert w.pipe.handle_event(event(w.folder / name, w.base + 15.0)).level == CLEAN
    w.pipe.tick(w.base + 19.0)                    # only 4 seconds old: not trusted yet
    decoy_attack(w, w.base + 20.0)
    assert (w.folder / name).read_bytes() == w.originals[name], \
        "by design an edit younger than ~10 s must roll back to the snapshot version"
