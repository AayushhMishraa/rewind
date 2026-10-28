import ast
import glob
import os
import random

import pytest

import config
from core.events import CLEAN, CONFIRMED, SUSPICIOUS, FileEvent, Verdict
from detection.decoy_monitor import MARKER, DecoyMonitor
from detection.detection_engine import get_confidence
from detection.speed_checker import SpeedChecker
from detection.suspicion_tracker import SuspicionTracker
from generate_samples import make_document_text
from recovery.manifest import Manifest, build_manifest


# ---------- helpers ----------
def make_folder(tmp_path, n=100):
    folder = tmp_path / "protected"
    folder.mkdir()
    rng = random.Random(7)
    for i in range(n):
        (folder / ("document_%03d.txt" % i)).write_bytes(
            make_document_text(i, rng).encode("utf-8"))
    manifest = Manifest(root=str(folder), data=build_manifest(str(folder)))
    return folder, manifest


def ev(path, t, pid=100, kind="modified", dest=None):
    return FileEvent(path=str(path), event_type=kind, timestamp=t, pid=pid, dest_path=dest)


def parts(folder):
    return SpeedChecker(), SuspicionTracker(), DecoyMonitor(str(folder))


def doc(folder, i):
    return str(folder / ("document_%03d.txt" % i))


# ---------- speed checker ----------
def test_24_files_is_no_signal_and_25_is_speed():
    sc = SpeedChecker()
    for i in range(24):
        sc.record_event(1, "f%d" % i, i * 0.1)
    assert sc.get_score(1, now=2.4) is False
    sc.record_event(1, "f24", 2.4)
    assert sc.get_score(1, now=2.4) is True


def test_same_file_many_times_counts_once():
    sc = SpeedChecker()
    for i in range(100):
        sc.record_event(1, "same.txt", i * 0.01)
    assert sc.count(1, now=1.0) == 1
    assert sc.get_score(1, now=1.0) is False


def test_old_events_expire_after_the_window():
    sc = SpeedChecker()
    for i in range(25):
        sc.record_event(1, "f%d" % i, i * 0.01)
    assert sc.get_score(1, now=0.3) is True
    assert sc.get_score(1, now=6.0) is False


def test_finished_burst_does_not_keep_the_alarm_alive():
    sc = SpeedChecker()
    for i in range(25):
        sc.record_event(1, "f%d" % i, i * 0.01)   # burst at t=0..0.24
    assert sc.get_score(1, now=0.5) is True
    assert sc.get_score(1, now=3.0) is False      # still inside 5s, but burst is over


def test_actors_are_counted_separately():
    sc = SpeedChecker()
    for i in range(25):
        sc.record_event(1, "a%d" % i, i * 0.05)
    for i in range(5):
        sc.record_event(2, "b%d" % i, i * 0.05)
    assert sc.get_score(1, now=1.3) is True
    assert sc.get_score(2, now=1.3) is False


# ---------- suspicion tracker ----------
def test_tracker_sustained_after_three_unbroken_seconds():
    tr = SuspicionTracker()
    for t in (0, 1, 2):
        tr.note("a", t)
        assert tr.is_sustained("a", t) is False
    tr.note("a", 3)
    assert tr.is_sustained("a", 3) is True


def test_tracker_gap_longer_than_two_seconds_resets_the_timer():
    tr = SuspicionTracker()
    for t in (0, 1, 2):
        tr.note("a", t)
    tr.note("a", 4.5)                       # 2.5 s gap -> restart
    assert tr.is_sustained("a", 4.5) is False
    for t in (5.5, 6.5):
        tr.note("a", t)
        assert tr.is_sustained("a", t) is False
    tr.note("a", 7.5)
    assert tr.is_sustained("a", 7.5) is True


def test_tracker_gap_of_exactly_two_seconds_does_not_reset():
    tr = SuspicionTracker()
    for t in (0, 2, 4):
        tr.note("a", t)
    assert tr.is_sustained("a", 4) is True


def test_tracker_goes_stale_when_activity_stops():
    tr = SuspicionTracker()
    for t in (0, 1, 2, 3):
        tr.note("a", t)
    assert tr.is_sustained("a", 3) is True
    assert tr.is_sustained("a", 6) is False


def test_tracker_actors_are_independent():
    tr = SuspicionTracker()
    for t in (0, 1, 2, 3):
        tr.note("a", t)
    assert tr.is_sustained("a", 3) is True
    assert tr.is_sustained("b", 3) is False


# ---------- decoys ----------
def test_planted_decoys_sort_first_are_big_and_marked(tmp_path):
    folder, _ = make_folder(tmp_path, n=5)
    dm = DecoyMonitor(str(folder))
    planted = dm.plant_decoys()
    assert len(planted) == 3
    assert sorted(os.listdir(folder))[0].startswith("!DECOY_")
    for p in planted:
        assert os.path.getsize(p) >= 4096
        assert MARKER in open(p, encoding="utf-8").read()


def test_one_decoy_is_planted_in_each_subfolder(tmp_path):
    folder, _ = make_folder(tmp_path, n=3)
    (folder / "sub").mkdir()
    (folder / ".hidden").mkdir()
    planted = DecoyMonitor(str(folder)).plant_decoys()
    assert len(planted) == 4
    assert any(os.path.dirname(p) == str(folder / "sub") for p in planted)
    assert not any(".hidden" in p for p in planted)


@pytest.mark.parametrize("kind", ["modified", "deleted", "moved"])
def test_touching_a_decoy_is_instantly_confirmed(tmp_path, kind):
    folder, manifest = make_folder(tmp_path, n=5)
    sc, tr, dm = parts(folder)
    decoys = dm.plant_decoys()
    v = get_confidence(ev(decoys[0], 1.0, kind=kind), sc, manifest, tr, dm)
    assert v.level == CONFIRMED and v.signals == ["DECOY"]


def test_moving_a_file_onto_a_decoy_is_confirmed(tmp_path):
    folder, manifest = make_folder(tmp_path, n=5)
    sc, tr, dm = parts(folder)
    decoys = dm.plant_decoys()
    v = get_confidence(ev(doc(folder, 0), 1.0, kind="moved", dest=decoys[1]),
                       sc, manifest, tr, dm)
    assert v.level == CONFIRMED and v.signals == ["DECOY"]


def test_ordinary_activity_is_not_a_decoy_touch(tmp_path):
    folder, manifest = make_folder(tmp_path, n=5)
    sc, tr, dm = parts(folder)
    dm.plant_decoys()
    v = get_confidence(ev(doc(folder, 0), 1.0), sc, manifest, tr, dm)
    assert v.level == CLEAN and v.signals == []
    assert isinstance(v, Verdict)


# ---------- combiner ----------
def test_new_files_never_count_towards_speed(tmp_path):
    folder, manifest = make_folder(tmp_path, n=5)
    sc, tr, dm = parts(folder)
    for i in range(40):
        kind = "created" if i % 2 == 0 else "modified"
        v = get_confidence(ev(folder / ("backup_%d.zip" % i), 10 + i * 0.01, kind=kind),
                           sc, manifest, tr, dm)
        assert v.level == CLEAN
    assert sc.count(config.FOLDER_WIDE_ACTOR, now=10.5) == 0


def test_speed_plus_entropy_is_confirmed(tmp_path):
    folder, manifest = make_folder(tmp_path)
    sc, tr, dm = parts(folder)
    verdicts = []
    for i in range(30):
        with open(doc(folder, i), "wb") as f:
            f.write(os.urandom(8192))              # simulated encryption
        verdicts.append(get_confidence(ev(doc(folder, i), 100 + i * 0.05),
                                       sc, manifest, tr, dm))
    for v in verdicts[:24]:                        # fewer than 25 files so far
        assert v.level == SUSPICIOUS and v.signals == ["ENTROPY"]
    assert verdicts[24].level == CONFIRMED
    assert verdicts[24].signals == ["SPEED", "ENTROPY"]
    assert verdicts[29].level == CONFIRMED


def test_speed_alone_is_only_suspicious(tmp_path):
    folder, manifest = make_folder(tmp_path)
    sc, tr, dm = parts(folder)
    verdicts = [get_confidence(ev(doc(folder, i), 100 + i * 0.05), sc, manifest, tr, dm)
                for i in range(30)]               # files are not actually changed
    assert all(v.level == CLEAN for v in verdicts[:24])
    for v in verdicts[24:]:
        assert v.level == SUSPICIOUS and v.signals == ["SPEED"]


def test_deleted_files_count_for_speed_but_never_for_entropy(tmp_path):
    folder, manifest = make_folder(tmp_path)
    sc, tr, dm = parts(folder)
    for i in range(30):
        with open(doc(folder, i), "wb") as f:
            f.write(os.urandom(8192))
    verdicts = [get_confidence(ev(doc(folder, i), 100 + i * 0.05, kind="deleted"),
                               sc, manifest, tr, dm) for i in range(30)]
    assert verdicts[24].signals == ["SPEED"] and verdicts[24].level == SUSPICIOUS


def test_one_signal_that_keeps_going_escalates_to_sustained(tmp_path):
    folder, manifest = make_folder(tmp_path)
    sc, tr, dm = parts(folder)
    verdicts = [get_confidence(ev(doc(folder, i), 100 + i * 0.05), sc, manifest, tr, dm)
                for i in range(100)]
    levels = [v.level for v in verdicts]
    first = levels.index(CONFIRMED)
    assert 80 <= first <= 90                       # about 3 s after the first alarm
    assert verdicts[first].signals == ["SPEED", "SUSTAINED"]
    assert all(l == CLEAN for l in levels[:24])
    assert all(l == SUSPICIOUS for l in levels[24:first])


def test_a_finished_burst_does_not_turn_later_normal_edits_into_an_attack(tmp_path):
    folder, manifest = make_folder(tmp_path)
    sc, tr, dm = parts(folder)
    for i in range(100):                           # e.g. a quick 'sed -i' over everything
        get_confidence(ev(doc(folder, i), 200 + i * 0.001), sc, manifest, tr, dm)
    v1 = get_confidence(ev(doc(folder, 0), 202.0), sc, manifest, tr, dm)
    v2 = get_confidence(ev(doc(folder, 1), 203.1), sc, manifest, tr, dm)
    assert v1.level == CLEAN and v2.level == CLEAN


def test_speed_is_caught_even_when_the_work_is_split_across_processes(tmp_path):
    folder, manifest = make_folder(tmp_path)
    sc, tr, dm = parts(folder)
    verdicts = [get_confidence(ev(doc(folder, i), 100 + i * 0.05, pid=100 + (i % 6)),
                               sc, manifest, tr, dm) for i in range(30)]
    assert verdicts[24].level == SUSPICIOUS and verdicts[24].signals == ["SPEED"]
    assert verdicts[24].details["speed_actor"] == config.FOLDER_WIDE_ACTOR


def test_unattributed_events_are_still_scored(tmp_path):
    folder, manifest = make_folder(tmp_path)
    sc, tr, dm = parts(folder)
    verdicts = [get_confidence(ev(doc(folder, i), 100 + i * 0.05, pid=config.UNATTRIBUTED_PID),
                               sc, manifest, tr, dm) for i in range(30)]
    assert verdicts[24].signals == ["SPEED"]
    assert verdicts[24].details["speed_actor"] == config.UNATTRIBUTED_PID


def test_one_normal_edit_is_clean(tmp_path):
    folder, manifest = make_folder(tmp_path, n=5)
    sc, tr, dm = parts(folder)
    with open(doc(folder, 0), "ab") as f:
        f.write(b"one more sentence typed by a person.\n")
    v = get_confidence(ev(doc(folder, 0), 5.0), sc, manifest, tr, dm)
    assert v.level == CLEAN and v.signals == []


# ---------- rule R1: detection must never act ----------
def test_detection_code_never_imports_response_or_recovery():
    forbidden = {"response", "recovery", "watcher", "database"}
    files = glob.glob(os.path.join(config.BASE_DIR, "detection", "*.py"))
    files.append(os.path.join(config.BASE_DIR, "core", "events.py"))
    scanned = 0
    for path in files:
        if os.path.basename(path) == "__init__.py":
            continue
        scanned += 1
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            assert not (set(names) & forbidden), "%s imports %s" % (path, names)
    assert scanned >= 6
