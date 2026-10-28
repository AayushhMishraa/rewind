"""Snapshot manager: full backups of the protected folder.

A snapshot is only ever taken when everything is calm (rule R6):
- skipped if the threat state is not NORMAL, or an alert happened < 10 s ago
- built in 'snapshot_<ms>.tmp/', then renamed ONLY when finished
- thrown away if an alert happens while copying (checked before AND after rename)
- thrown away if any file has already turned into noise since the baseline

Layout:  safety_copies/snapshot_<ms>/data/...   the copied files
         safety_copies/snapshot_<ms>/manifest.json   fingerprints + timestamps
         safety_copies/snapshot_<ms>/.complete       "this snapshot is finished"
(Files go in data/ so a user file called 'manifest.json' can never collide.)
"""
import json
import os
import shutil
import threading
import time

import config
from core.logger import log
from recovery.manifest import build_manifest

SNAPSHOT_PREFIX = "snapshot_"
TMP_SUFFIX = ".tmp"
DATA_DIRNAME = "data"
MANIFEST_NAME = "manifest.json"
COMPLETE_NAME = ".complete"


def read_snapshot_info(snapshot_path):
    """Details of a finished snapshot, or None if it is unfinished or unreadable."""
    if not os.path.isfile(os.path.join(snapshot_path, COMPLETE_NAME)):
        return None
    try:
        with open(os.path.join(snapshot_path, MANIFEST_NAME), encoding="utf-8") as f:
            meta = json.load(f)
        completed = float(meta["completed_at"])
        started = float(meta.get("started_at", completed))
        files = meta["files"]
        if not isinstance(files, dict):
            return None
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return {"name": os.path.basename(snapshot_path), "path": snapshot_path,
            "started_at": started, "completed_at": completed, "files": files}


def list_complete_snapshots(safety_dir=None):
    """All finished snapshots, newest first."""
    safety_dir = safety_dir or config.SAFETY_DIR
    if not os.path.isdir(safety_dir):
        return []
    infos = []
    for name in os.listdir(safety_dir):
        if not name.startswith(SNAPSHOT_PREFIX) or name.endswith(TMP_SUFFIX):
            continue
        path = os.path.join(safety_dir, name)
        if os.path.islink(path) or not os.path.isdir(path):
            continue
        info = read_snapshot_info(path)
        if info:
            infos.append(info)
    infos.sort(key=lambda i: (i["completed_at"], i["name"]), reverse=True)
    return infos


class SnapshotManager:
    def __init__(self, state, manifest=None, known_good=None, protected_dir=None,
                 safety_dir=None, clock=time.time, keep=None, cooldown=None):
        self.state = state
        self.manifest = manifest
        self.known_good = known_good
        self.protected_dir = os.path.abspath(protected_dir or config.PROTECTED_DIR)
        self.safety_dir = os.path.abspath(safety_dir or config.SAFETY_DIR)
        self.clock = clock
        self.keep = config.SNAPSHOT_KEEP if keep is None else keep
        self.cooldown = (config.SNAPSHOT_COOLDOWN_AFTER_ALERT
                         if cooldown is None else cooldown)
        self.last_snapshot_time = None
        self._take_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    # ----- public -----
    def take_snapshot(self):
        """Take one snapshot. Returns its folder path, or None if skipped/discarded."""
        if not self._take_lock.acquire(blocking=False):
            return None                      # another snapshot is already running
        try:
            return self._take_snapshot_locked()
        finally:
            self._take_lock.release()

    def start_periodic(self, interval=None):
        """Take a snapshot every `interval` seconds in a background thread."""
        interval = config.SNAPSHOT_INTERVAL_SECONDS if interval is None else interval
        if self._thread is not None and self._thread.is_alive():
            return self._thread
        self._stop.clear()

        def loop():
            while not self._stop.wait(interval):
                try:
                    self.take_snapshot()
                except Exception as err:     # a background thread must never die silently
                    log("snapshot_error", error=str(err))

        self._thread = threading.Thread(target=loop, name="rewind-snapshots", daemon=True)
        self._thread.start()
        return self._thread

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    # ----- internals -----
    def _dir_for(self, stamp):
        return os.path.join(self.safety_dir, "%s%d" % (SNAPSHOT_PREFIX, stamp))

    def _still_safe(self, generation):
        return self.state.is_normal() and self.state.generation == generation

    def _take_snapshot_locked(self):
        started_at = self.clock()
        if not self.state.is_normal():
            log("snapshot_skipped", reason="threat state is %s" % self.state.state)
            return None
        if self.state.seconds_since_alert(started_at) < self.cooldown:
            log("snapshot_skipped", reason="too soon after an alert")
            return None
        generation = self.state.generation

        os.makedirs(self.safety_dir, exist_ok=True)
        self._remove_stale()
        stamp = int(started_at * 1000)
        while os.path.exists(self._dir_for(stamp)) or os.path.exists(self._dir_for(stamp) + TMP_SUFFIX):
            stamp += 1
        final_dir = self._dir_for(stamp)
        tmp_dir = final_dir + TMP_SUFFIX

        try:
            self._copy_tree(tmp_dir)
            files = build_manifest(os.path.join(tmp_dir, DATA_DIRNAME))
            if not self._still_safe(generation):
                return self._discard(tmp_dir, "threat state changed while copying")
            poisoned = self._poisoned_files(files)
            if poisoned:
                return self._discard(
                    tmp_dir, "files already turned to noise: " + ", ".join(sorted(poisoned)[:5]))
            completed_at = self.clock()
            with open(os.path.join(tmp_dir, MANIFEST_NAME), "w", encoding="utf-8") as f:
                json.dump({"started_at": started_at, "completed_at": completed_at,
                           "files": files}, f, sort_keys=True)
            os.replace(tmp_dir, final_dir)                 # atomic rename
            with open(os.path.join(final_dir, COMPLETE_NAME), "w", encoding="utf-8") as f:
                f.write("%r\n" % completed_at)
            if not self._still_safe(generation):           # last-moment check
                return self._discard(final_dir, "threat state changed at the last moment")
        except OSError as err:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            log("snapshot_failed", error=str(err))
            return None

        if self.manifest is not None:
            self.manifest.replace(files)                   # the new baseline
        if self.known_good is not None:
            self.known_good.clear_older_than(started_at)   # the snapshot already contains them
        self._apply_retention()
        self.last_snapshot_time = completed_at
        log("snapshot_taken", snapshot=os.path.basename(final_dir), files=len(files))
        return final_dir

    def _copy_tree(self, tmp_dir):
        data_dir = os.path.join(tmp_dir, DATA_DIRNAME)
        os.makedirs(data_dir)
        for dirpath, dirnames, filenames in os.walk(self.protected_dir):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
            rel_dir = os.path.relpath(dirpath, self.protected_dir)
            target_dir = data_dir if rel_dir == "." else os.path.join(data_dir, rel_dir)
            os.makedirs(target_dir, exist_ok=True)
            for name in sorted(filenames):
                if name.startswith("."):
                    continue
                src = os.path.join(dirpath, name)
                if os.path.islink(src):
                    continue
                try:
                    shutil.copy2(src, os.path.join(target_dir, name))
                except FileNotFoundError:
                    continue                 # deleted while we were copying

    def _poisoned_files(self, new_files):
        """Files that were readable at baseline but are noise now."""
        if self.manifest is None:
            return []
        bad = []
        for rel, entry in new_files.items():
            base = self.manifest.get(rel)
            if (base is not None
                    and entry["size"] >= config.ENTROPY_MIN_FILE_BYTES
                    and base["entropy"] < config.ENTROPY_BASELINE_MAX
                    and entry["entropy"] >= config.ENTROPY_THRESHOLD):
                bad.append(rel)
        return bad

    def _discard(self, path, reason):
        shutil.rmtree(path, ignore_errors=True)
        log("snapshot_discarded", reason=reason)
        return None

    def _remove_stale(self):
        """Delete leftovers from a crashed or interrupted snapshot."""
        for name in os.listdir(self.safety_dir):
            if not name.startswith(SNAPSHOT_PREFIX):
                continue
            path = os.path.join(self.safety_dir, name)
            if os.path.islink(path) or not os.path.isdir(path):
                continue
            if name.endswith(TMP_SUFFIX) or not os.path.isfile(os.path.join(path, COMPLETE_NAME)):
                shutil.rmtree(path, ignore_errors=True)
                log("snapshot_stale_removed", snapshot=name)

    def _apply_retention(self):
        for old in list_complete_snapshots(self.safety_dir)[self.keep:]:
            shutil.rmtree(old["path"], ignore_errors=True)
            log("snapshot_pruned", snapshot=old["name"])


def take_snapshot(manager):
    """Spec-style helper: take one snapshot with the given manager."""
    return manager.take_snapshot()


def start_periodic_snapshots(manager, interval=None):
    """Spec-style helper: start the background snapshot thread."""
    return manager.start_periodic(interval)
