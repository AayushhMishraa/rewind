import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

import config
from core.state import ELEVATED, NORMAL, RESPONDING, ThreatState
from detection.decoy_monitor import DecoyMonitor
from generate_samples import generate, make_document_text
from recovery.known_good import KnownGoodTracker
from recovery.manifest import Manifest, build_manifest, sha256_file
from recovery.restore_engine import restore_all
from recovery.snapshot_manager import (COMPLETE_NAME, DATA_DIRNAME, MANIFEST_NAME,
                                       SnapshotManager, list_complete_snapshots)
from tools.verify_restore import verify
from watcher.watcher_control import WatcherControl


# ---------------- helpers ----------------
class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def sha_of(path):
    return sha256_file(str(path))


def make_world(tmp_path, n=20, with_decoys=True):
    folder = tmp_path / "protected"
    folder.mkdir()
    safety = tmp_path / "safety"
    rng = random.Random(3)
    originals = {}
    for i in range(n):
        name = "document_%03d.txt" % i
        (folder / name).write_bytes(make_document_text(i, rng).encode("utf-8"))
        originals[name] = sha_of(folder / name)
    if with_decoys:
        DecoyMonitor(str(folder)).plant_decoys()      # adds 3 decoy files
    clock = FakeClock(1000.0)
    state = ThreatState(clock=clock)
    manifest = Manifest(root=str(folder), data=build_manifest(str(folder)))
    tracker = KnownGoodTracker(str(folder), str(safety), promote_after=0)  # older tests expect instant trust
    snaps = SnapshotManager(state, manifest=manifest, known_good=tracker,
                            protected_dir=str(folder), safety_dir=str(safety), clock=clock)
    return SimpleNamespace(folder=folder, safety=safety, originals=originals, clock=clock,
                           state=state, manifest=manifest, tracker=tracker, snaps=snaps)


def snap_at(w, t):
    w.clock.t = t
    path = w.snaps.take_snapshot()
    assert path is not None
    return path


def encrypt(folder, names):
    for name in names:
        (folder / name).write_bytes(os.urandom(8192))


def do_restore(w, attack_time, **kw):
    kw.setdefault("control", WatcherControl())
    kw.setdefault("settle_seconds", 0)
    return restore_all(attack_time, protected_dir=str(w.folder), safety_dir=str(w.safety),
                       manifest=w.manifest, **kw)


def all_original(w):
    return all(sha_of(w.folder / n) == h for n, h in w.originals.items())


# ---------------- threat state ----------------
def test_state_transitions():
    st = ThreatState(clock=lambda: 50.0)
    assert st.state == NORMAL and st.is_normal() and st.episode_start is None
    assert st.seconds_since_alert(100) == float("inf")
    g = st.generation
    st.raise_elevated(now=10)
    assert st.state == ELEVATED and st.episode_start == 10 and st.generation > g
    st.raise_elevated(now=12)
    assert st.episode_start == 10 and st.last_alert_time == 12   # same episode
    st.start_responding(now=13)
    assert st.state == RESPONDING
    st.return_to_normal(now=20)
    assert st.state == NORMAL and st.episode_start is None
    assert st.seconds_since_alert(25) == 5


def test_a_direct_confirmation_also_starts_an_episode():
    st = ThreatState()
    st.start_responding(now=5)
    assert st.state == RESPONDING and st.episode_start == 5


# ---------------- watcher pause switch ----------------
def test_pause_switch_and_nesting():
    c = WatcherControl(clock=lambda: 100.0)
    assert not c.is_paused()
    with c.paused():
        assert c.is_paused()
        with c.paused():
            assert c.is_paused()
        assert c.is_paused()          # inner pause ended, outer still active
    assert not c.is_paused()
    assert c.resumed_at == 100.0


def test_events_from_before_the_resume_are_dropped():
    c = WatcherControl(clock=lambda: 100.0)
    c.pause()
    assert c.should_drop(500.0) is True      # paused: everything is dropped
    c.resume()
    assert c.should_drop(99.0) is True       # queued during the pause
    assert c.should_drop(100.5) is False     # genuinely new


# ---------------- snapshots ----------------
def test_snapshot_is_complete_and_listed(tmp_path):
    w = make_world(tmp_path)
    path = snap_at(w, 1000)
    assert os.path.isfile(os.path.join(path, COMPLETE_NAME))
    assert os.path.isfile(os.path.join(path, MANIFEST_NAME))
    data = os.path.join(path, DATA_DIRNAME)
    for name, digest in w.originals.items():
        assert sha256_file(os.path.join(data, name)) == digest
    assert any(n.startswith("!DECOY_") for n in os.listdir(data))
    infos = list_complete_snapshots(str(w.safety))
    assert len(infos) == 1 and infos[0]["completed_at"] == 1000
    assert len(infos[0]["files"]) == 23          # 20 documents + 3 decoys
    assert not [n for n in os.listdir(w.safety) if n.endswith(".tmp")]


def test_snapshot_is_skipped_unless_state_is_normal(tmp_path):
    w = make_world(tmp_path)
    w.state.raise_elevated(now=1000)
    w.clock.t = 1100
    assert w.snaps.take_snapshot() is None
    w.state.start_responding(now=1101)
    assert w.snaps.take_snapshot() is None
    assert list_complete_snapshots(str(w.safety)) == []


def test_snapshot_is_skipped_right_after_an_alert(tmp_path):
    w = make_world(tmp_path)
    w.state.raise_elevated(now=1000)
    w.state.return_to_normal(now=1001)
    w.clock.t = 1005                                  # 4 seconds after the alert
    assert w.snaps.take_snapshot() is None
    w.clock.t = 1012                                  # 11 seconds after
    assert w.snaps.take_snapshot() is not None


def test_snapshot_is_discarded_if_an_alert_happens_mid_copy(tmp_path, monkeypatch):
    w = make_world(tmp_path)
    real_copy = shutil.copy2
    count = {"n": 0}

    def sneaky(src, dst, *a, **k):
        count["n"] += 1
        if count["n"] == 3:
            w.state.raise_elevated(now=1000.5)        # alarm goes off mid-copy
        return real_copy(src, dst, *a, **k)

    monkeypatch.setattr(shutil, "copy2", sneaky)
    w.clock.t = 1000
    assert w.snaps.take_snapshot() is None
    assert count["n"] >= 3
    assert [n for n in os.listdir(w.safety) if n.startswith("snapshot_")] == []


def test_snapshot_is_refused_if_files_have_already_turned_to_noise(tmp_path):
    w = make_world(tmp_path)
    encrypt(w.folder, ["document_000.txt", "document_001.txt"])
    w.clock.t = 1000
    assert w.snaps.take_snapshot() is None
    assert list_complete_snapshots(str(w.safety)) == []


def test_only_the_newest_five_snapshots_are_kept(tmp_path):
    w = make_world(tmp_path)
    for i in range(7):
        snap_at(w, 1000 + i * 100)
    infos = list_complete_snapshots(str(w.safety))
    assert [i["completed_at"] for i in infos] == [1600, 1500, 1400, 1300, 1200]


def test_a_good_snapshot_updates_the_baseline_and_prunes_old_live_copies(tmp_path):
    w = make_world(tmp_path)
    new_file = w.folder / "new_file.txt"
    new_file.write_text("fresh content " * 300)
    assert not w.manifest.contains(str(new_file))
    assert w.tracker.track(str(w.folder / "document_000.txt"))
    assert w.tracker.track(str(w.folder / "document_001.txt"))
    live0 = w.safety / "live" / "document_000.txt"
    live1 = w.safety / "live" / "document_001.txt"
    os.utime(live0, (900, 900))          # older than the snapshot
    os.utime(live1, (1500, 1500))        # newer than the snapshot
    snap_at(w, 1000)
    assert w.manifest.contains(str(new_file))
    assert not live0.exists() and live1.exists()


def test_leftovers_from_a_crashed_snapshot_are_cleaned_up(tmp_path):
    w = make_world(tmp_path)
    os.makedirs(w.safety / "snapshot_5.tmp")
    (w.safety / "snapshot_5.tmp" / "x").write_text("x")
    os.makedirs(w.safety / "snapshot_6")             # looks finished but has no marker
    snap_at(w, 1000)
    names = os.listdir(w.safety)
    assert "snapshot_5.tmp" not in names and "snapshot_6" not in names
    assert len(list_complete_snapshots(str(w.safety))) == 1


def test_periodic_snapshots_run_in_the_background(tmp_path):
    w = make_world(tmp_path)
    w.snaps.start_periodic(interval=0.05)
    deadline = time.time() + 5
    while len(list_complete_snapshots(str(w.safety))) < 2 and time.time() < deadline:
        time.sleep(0.05)
    w.snaps.stop()
    assert len(list_complete_snapshots(str(w.safety))) >= 2


# ---------------- known-good copies ----------------
def test_known_good_saves_a_clean_edited_file(tmp_path):
    w = make_world(tmp_path, n=3)
    p = w.folder / "document_000.txt"
    p.write_bytes(p.read_bytes() + b"a legitimate edit\n")
    assert w.tracker.track(str(p)) is True
    assert (w.safety / "live" / "document_000.txt").read_bytes() == p.read_bytes()


def test_known_good_never_saves_noise_and_keeps_the_old_good_copy(tmp_path):
    w = make_world(tmp_path, n=3)
    p = w.folder / "document_000.txt"
    live = w.safety / "live" / "document_000.txt"
    assert w.tracker.track(str(p))
    good = live.read_bytes()
    p.write_bytes(os.urandom(8192))                   # now it looks encrypted
    assert w.tracker.track(str(p)) is False
    assert live.read_bytes() == good
    assert not [f for f in os.listdir(live.parent) if f.endswith(".part")]


def test_small_files_must_be_valid_text_to_be_saved(tmp_path):
    w = make_world(tmp_path, n=3)
    note = w.folder / "note.txt"
    note.write_text("just a short note\n")
    assert w.tracker.track(str(note)) is True
    tiny = w.folder / "tiny.bin"
    tiny.write_bytes(os.urandom(100))
    assert w.tracker.track(str(tiny)) is False


def test_known_good_ignores_ineligible_paths(tmp_path):
    w = make_world(tmp_path, n=3)
    outside = tmp_path / "outside.txt"
    outside.write_text("x" * 100)
    assert w.tracker.track(str(outside)) is False                 # outside the folder
    hidden = w.folder / ".hidden.txt"
    hidden.write_text("x" * 100)
    assert w.tracker.track(str(hidden)) is False                  # dotfile
    decoy = sorted(w.folder.glob("!DECOY_*"))[0]
    assert w.tracker.track(str(decoy)) is False                   # decoy
    link = w.folder / "link.txt"
    os.symlink(str(outside), str(link))
    assert w.tracker.track(str(link)) is False                    # symlink
    assert w.tracker.list_live() == {}


def test_known_good_clear_older_than(tmp_path):
    w = make_world(tmp_path, n=3)
    for i, mtime in enumerate((100, 200, 300)):
        name = "document_%03d.txt" % i
        assert w.tracker.track(str(w.folder / name))
        os.utime(w.safety / "live" / name, (mtime, mtime))
    w.tracker.clear_older_than(250)
    assert sorted(w.tracker.list_live()) == ["document_002.txt"]
    w.tracker.clear()
    assert w.tracker.list_live() == {}


# ---------------- restore ----------------
def test_restore_puts_every_file_back_byte_for_byte(tmp_path):
    w = make_world(tmp_path)
    snap_at(w, 1000)
    names = ["document_%03d.txt" % i for i in range(10)]
    encrypt(w.folder, names)
    assert not all_original(w)
    res = do_restore(w, 1010)
    assert res.verified is True and res.error is None and res.failed == []
    assert res.restored == sorted(names)
    assert res.snapshot_used.startswith("snapshot_")
    assert all_original(w)


def test_restore_leaves_already_correct_files_alone(tmp_path):
    w = make_world(tmp_path)
    snap_at(w, 1000)
    before = os.stat(w.folder / "document_015.txt").st_mtime_ns
    encrypt(w.folder, ["document_000.txt"])
    res = do_restore(w, 1010)
    assert res.restored == ["document_000.txt"]
    assert os.stat(w.folder / "document_015.txt").st_mtime_ns == before


def test_a_snapshot_taken_after_the_attack_began_is_ignored(tmp_path):
    w = make_world(tmp_path)
    first = snap_at(w, 1000)
    p = w.folder / "document_000.txt"
    p.write_bytes(p.read_bytes() + b"a later edit\n")
    snap_at(w, 1020)                                  # newer, but after the attack at 1010
    encrypt(w.folder, ["document_001.txt"])
    res = do_restore(w, 1010)
    assert res.snapshot_used == os.path.basename(first)
    assert "document_000.txt" in res.restored         # went back to the older version
    assert all_original(w)


def test_a_poisoned_snapshot_is_rejected_and_an_older_one_is_used(tmp_path):
    w = make_world(tmp_path)
    good = snap_at(w, 1000)
    bad = os.path.join(str(w.safety), "snapshot_1005000")
    shutil.copytree(good, bad)
    data_bad = os.path.join(bad, DATA_DIRNAME)
    docs = [n for n in sorted(os.listdir(data_bad)) if n.startswith("document_")][:8]
    for name in docs:                                  # 8 of 23 files = 35% noise
        with open(os.path.join(data_bad, name), "wb") as f:
            f.write(os.urandom(8192))
    with open(os.path.join(bad, MANIFEST_NAME), "w", encoding="utf-8") as f:
        json.dump({"started_at": 1005, "completed_at": 1005,
                   "files": build_manifest(data_bad)}, f)
    with open(os.path.join(bad, COMPLETE_NAME), "w", encoding="utf-8") as f:
        f.write("1005.0\n")
    assert len(list_complete_snapshots(str(w.safety))) == 2
    encrypt(w.folder, ["document_000.txt", "document_001.txt"])
    res = do_restore(w, 1010)
    assert res.snapshot_used == os.path.basename(good)
    assert res.verified is True and all_original(w)


def test_restore_reports_an_error_when_there_is_no_snapshot(tmp_path):
    w = make_world(tmp_path, n=3)
    encrypt(w.folder, ["document_000.txt"])
    res = do_restore(w, 1010)
    assert res.error and res.verified is False and res.restored == []
    assert res.snapshot_used is None
    assert sha_of(w.folder / "document_000.txt") != w.originals["document_000.txt"]


def test_a_snapshot_that_only_exists_after_the_attack_is_unusable(tmp_path):
    w = make_world(tmp_path, n=3)
    snap_at(w, 1020)
    encrypt(w.folder, ["document_000.txt"])
    res = do_restore(w, 1010)
    assert res.error and res.verified is False and res.snapshot_used is None


def test_a_newer_live_copy_keeps_your_legitimate_edit(tmp_path):
    w = make_world(tmp_path)
    snap_at(w, 1000)
    p = w.folder / "document_003.txt"
    edited = p.read_bytes() + b"my legitimate edit\n"
    p.write_bytes(edited)
    assert w.tracker.track(str(p))
    os.utime(w.safety / "live" / "document_003.txt", (1005, 1005))
    encrypt(w.folder, ["document_003.txt", "document_004.txt"])
    res = do_restore(w, 1010)
    assert res.verified is True
    assert p.read_bytes() == edited                                 # your edit survived
    assert sha_of(w.folder / "document_004.txt") == w.originals["document_004.txt"]


def test_a_live_copy_older_than_the_snapshot_is_not_used(tmp_path):
    w = make_world(tmp_path)
    snap_at(w, 1000)
    p = w.folder / "document_003.txt"
    p.write_bytes(p.read_bytes() + b"stale edit\n")
    assert w.tracker.track(str(p))
    os.utime(w.safety / "live" / "document_003.txt", (990, 990))
    encrypt(w.folder, ["document_003.txt"])
    do_restore(w, 1010)
    assert sha_of(p) == w.originals["document_003.txt"]


def test_alien_files_created_after_the_attack_are_quarantined_not_deleted(tmp_path):
    w = make_world(tmp_path)
    snap_at(w, 1000)
    legit = w.folder / "notes_new.txt"
    legit.write_text("a legitimate new file made before the attack")
    time.sleep(0.1)
    attack_time = time.time()
    time.sleep(0.1)
    locked = w.folder / "document_001.txt.locked"
    locked.write_bytes(os.urandom(100))
    encrypt(w.folder, ["document_001.txt"])
    res = do_restore(w, attack_time, margin_seconds=0, trace_id="t1")
    assert legit.exists()                                           # legit file untouched
    assert not locked.exists()
    assert (w.safety / "quarantine" / "t1" / "document_001.txt.locked").exists()
    assert res.quarantined == ["document_001.txt.locked"]
    assert sha_of(w.folder / "document_001.txt") == w.originals["document_001.txt"]


def test_the_watcher_is_paused_for_the_whole_restore(tmp_path, monkeypatch):
    w = make_world(tmp_path)
    snap_at(w, 1000)
    control = WatcherControl()
    seen = []
    real_copy = shutil.copy2

    def spy(src, dst, *a, **k):
        seen.append(control.is_paused())
        return real_copy(src, dst, *a, **k)

    monkeypatch.setattr(shutil, "copy2", spy)
    encrypt(w.folder, ["document_000.txt", "document_001.txt"])
    res = do_restore(w, 1010, control=control)
    assert res.verified is True
    assert seen and all(seen)
    assert not control.is_paused()
    assert control.should_drop(control.resumed_at - 0.01) is True


def test_a_tampered_manifest_cannot_write_outside_the_folder(tmp_path):
    w = make_world(tmp_path, n=2, with_decoys=False)
    snap = snap_at(w, 1000)
    secret = b"escaped content\n"
    with open(os.path.join(snap, "escape.txt"), "wb") as f:
        f.write(secret)
    mpath = os.path.join(snap, MANIFEST_NAME)
    with open(mpath, encoding="utf-8") as f:
        meta = json.load(f)
    meta["files"]["../escape.txt"] = {"sha256": hashlib.sha256(secret).hexdigest(),
                                      "size": len(secret), "entropy": 1.0}
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(meta, f)
    res = do_restore(w, 1010)
    assert "../escape.txt" in res.failed and res.verified is False
    assert not (tmp_path / "escape.txt").exists()


def test_a_damaged_backup_file_is_reported_not_trusted(tmp_path):
    w = make_world(tmp_path)
    snap = snap_at(w, 1000)
    with open(os.path.join(snap, DATA_DIRNAME, "document_002.txt"), "ab") as f:
        f.write(b"tampered")
    encrypt(w.folder, ["document_002.txt", "document_003.txt"])
    res = do_restore(w, 1010)
    assert res.failed == ["document_002.txt"] and res.verified is False
    assert "document_003.txt" in res.restored
    assert sha_of(w.folder / "document_003.txt") == w.originals["document_003.txt"]


def test_the_baseline_manifest_is_rebuilt_after_a_restore(tmp_path):
    w = make_world(tmp_path)
    snap_at(w, 1000)
    encrypt(w.folder, ["document_000.txt"])
    do_restore(w, 1010)
    entry = w.manifest.get(str(w.folder / "document_000.txt"))
    assert entry["sha256"] == w.originals["document_000.txt"]


# ---------------- the independent verify tool ----------------
def make_verify_world(tmp_path):
    paths = dict(protected_dir=str(tmp_path / "p"), safety_dir=str(tmp_path / "s"),
                 hashes_path=str(tmp_path / "d" / "h.json"),
                 db_path=str(tmp_path / "t.db"), log_path=str(tmp_path / "t.log"))
    generate(count=10, **paths)
    return paths


def test_verify_tool_counts_matches_problems_and_extras(tmp_path):
    p = make_verify_world(tmp_path)
    assert verify(p["protected_dir"], p["hashes_path"]) == (10, 10, [], [])
    with open(os.path.join(p["protected_dir"], "document_002.txt"), "ab") as f:
        f.write(b"x")
    os.remove(os.path.join(p["protected_dir"], "document_005.txt"))
    with open(os.path.join(p["protected_dir"], "x.locked"), "w") as f:
        f.write("junk")
    with open(os.path.join(p["protected_dir"], "!DECOY_001.txt"), "w") as f:
        f.write("bait")
    matched, total, problems, extras = verify(p["protected_dir"], p["hashes_path"])
    assert (matched, total) == (8, 10)
    assert problems == [("CHANGED", "document_002.txt"), ("MISSING", "document_005.txt")]
    assert extras == ["x.locked"]                       # decoys are ignored


def test_verify_tool_command_line(tmp_path):
    p = make_verify_world(tmp_path)
    script = os.path.join(config.BASE_DIR, "tools", "verify_restore.py")
    cmd = [sys.executable, script, "--dir", p["protected_dir"], "--hashes", p["hashes_path"]]
    ok = subprocess.run(cmd, capture_output=True, text=True, cwd=config.BASE_DIR)
    assert ok.returncode == 0 and "10/10 match" in ok.stdout
    with open(os.path.join(p["protected_dir"], "document_000.txt"), "ab") as f:
        f.write(b"x")
    bad = subprocess.run(cmd, capture_output=True, text=True, cwd=config.BASE_DIR)
    assert bad.returncode == 1 and "9/10 match" in bad.stdout
