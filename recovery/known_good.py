"""Known-good tracker: keeps the latest TRUSTED version of files you legitimately edit.

WHY NOT 'copy on first write': a file watcher only reports a change AFTER it happened, so
copying then would copy the already-damaged file. We copy only after a CLEAN verdict.

TRUST RULES (these close the "poisoned known-good" hole):
1. DELAY. A copy made after a CLEAN verdict is only PENDING (safety_copies/live_pending/).
     It becomes TRUSTED (safety_copies/live/) only after PROMOTE_AFTER_SECONDS with no
     alert. Any alert (note_alert) throws away every copy that has not aged enough yet.
2. CROSS-CHECK. Before a copy is trusted it is compared with the newest snapshot's version
     of the same file. If it differs too much in EITHER direction (entropy moved by more
     than MAX_ENTROPY_SHIFT, or size by more than MAX_SIZE_SHIFT) it is rejected. If it is
     byte-identical to the snapshot it is dropped (the snapshot already has it). A file the
     snapshot does not have falls back to the plain looks_clean() check.
A restore only ever reads the TRUSTED folder (list_live).

KNOWN TRADE-OFFS (pinned by tests):
  (a) an edit made in the ~10 s before an attack is rolled back to the snapshot version;
  (b) a slow wiper is NOT detected by this: the rules only stop a later restore from
      bringing its damage back as "legitimate".
"""
import os
import shutil
import threading
import time

import config
from core.logger import log
from detection.entropy_checker import calculate_entropy
from recovery.manifest import sha256_file
from recovery.snapshot_manager import list_complete_snapshots

LIVE_DIRNAME = "live"                # TRUSTED copies: the only ones a restore may use
PENDING_DIRNAME = "live_pending"     # copies still waiting to be trusted
PART_SUFFIX = ".part"

PROMOTE_AFTER_SECONDS = 10           # a copy must survive this long with no alert
MAX_ENTROPY_SHIFT = 0.5              # |entropy change| allowed versus the snapshot
MAX_SIZE_SHIFT = 0.05                # |size change| allowed versus the snapshot (5%)


def looks_clean(path):
    """True if a saved copy looks like normal content rather than encrypted noise.

    Big files: entropy must be below the alarm threshold.
    Small files (entropy is unreliable): they must be valid UTF-8 text.
    """
    try:
        size = os.path.getsize(path)
        if size >= config.ENTROPY_MIN_FILE_BYTES:
            return calculate_entropy(path) < config.ENTROPY_THRESHOLD
        with open(path, "rb") as f:
            f.read().decode("utf-8")
        return True
    except (OSError, UnicodeDecodeError):
        return False


class KnownGoodTracker:
    def __init__(self, protected_dir=None, safety_dir=None, promote_after=None):
        self.protected_dir = os.path.abspath(protected_dir or config.PROTECTED_DIR)
        self.safety_dir = os.path.abspath(safety_dir or config.SAFETY_DIR)
        self.live_dir = os.path.join(self.safety_dir, LIVE_DIRNAME)
        self.pending_dir = os.path.join(self.safety_dir, PENDING_DIRNAME)
        self.promote_after = (PROMOTE_AFTER_SECONDS if promote_after is None
                              else promote_after)
        self._pending = {}             # relative path -> {"path": copy on disk, "event_ts": time}
        self._lock = threading.RLock()

    def _relative(self, path):
        """Path relative to the protected folder, or None if the file must be ignored."""
        path = os.path.abspath(path)
        if os.path.islink(path):
            return None
        root_real = os.path.realpath(self.protected_dir)
        real = os.path.realpath(path)
        if os.path.commonpath([real, root_real]) != root_real:
            return None                       # outside the protected folder
        rel = os.path.relpath(real, root_real)
        if any(part.startswith(".") for part in rel.split(os.sep)):
            return None                       # dotfiles (like the sandbox marker)
        if os.path.basename(rel).startswith(config.DECOY_PREFIX):
            return None                       # decoys are bait, not user data
        return rel

    # ------------------------------------------------------------ staging and trust
    def track(self, path, now=None):
        """Stage a copy of a file that just got a CLEAN verdict. True if a copy was kept.

        `now` is the event's timestamp (the pipeline passes it; default: the real clock).
        The copy is only PENDING: it is trusted after `promote_after` seconds with no alert.
        """
        now = time.time() if now is None else now
        rel = self._relative(path)
        if rel is None or not os.path.isfile(path):
            return False
        dest = os.path.join(self.pending_dir, rel)
        part = dest + PART_SUFFIX
        with self._lock:
            try:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copyfile(path, part)          # new mtime = time of copying
                if not looks_clean(part):            # re-check the COPY, not the original
                    os.remove(part)
                    log("known_good_rejected", path=rel, reason="copy looks like noise")
                    return False
                os.replace(part, dest)
            except OSError:
                self._remove_quietly(part)
                return False
            self._pending[rel] = {"path": dest, "event_ts": now}
            self._promote_due_locked(now)            # (with promote_after=0 this is instant)
        return True

    def note_alert(self, now=None):
        """Something suspicious happened: copies that have not aged enough are NOT trusted."""
        now = time.time() if now is None else now
        with self._lock:
            self._promote_due_locked(now)    # copies already old enough were alert-free: keep
            dropped = self._discard_pending_locked()
        if dropped:
            log("known_good_discarded", count=dropped, reason="alert before the copies aged")

    def promote_due(self, now=None):
        """Trust every pending copy that is old enough (and passes the cross-check)."""
        now = time.time() if now is None else now
        with self._lock:
            self._promote_due_locked(now)

    def _promote_due_locked(self, now):
        due = [rel for rel, item in self._pending.items()
               if now - item["event_ts"] >= self.promote_after]
        if not due:
            return
        reference = self._snapshot_files()           # read the newest snapshot once per batch
        for rel in sorted(due):
            item = self._pending.pop(rel)
            decision, reason = self._cross_check(item["path"], reference.get(rel))
            if decision == "trust":
                self._move_to_live(rel, item["path"])
            else:
                self._remove_quietly(item["path"])
                log("known_good_rejected" if decision == "reject" else "known_good_dropped",
                    path=rel, reason=reason)
        self._prune_empty_dirs(self.pending_dir)

    def _cross_check(self, copy_path, ref):
        """Compare a pending copy with the snapshot's entry for the same file.

        Returns ("trust" | "reject" | "drop", reason).
        """
        if ref is None:
            return "trust", "no snapshot version to compare with"
        try:
            if sha256_file(copy_path) == ref["sha256"]:
                return "drop", "identical to the snapshot (nothing to add)"
            entropy_shift = abs(calculate_entropy(copy_path) - ref["entropy"])
            size_shift = abs(os.path.getsize(copy_path) - ref["size"]) / max(ref["size"], 1)
        except (OSError, KeyError, TypeError):
            return "reject", "could not compare with the snapshot"
        if entropy_shift > MAX_ENTROPY_SHIFT:        # catches BOTH directions
            return "reject", "entropy moved %.2f versus the snapshot" % entropy_shift
        if size_shift > MAX_SIZE_SHIFT:
            return "reject", "size moved %.1f%% versus the snapshot" % (size_shift * 100)
        return "trust", "close to the snapshot version"

    def _snapshot_files(self):
        """The newest finished snapshot's file table ({relative path: sha256/size/entropy})."""
        snapshots = list_complete_snapshots(self.safety_dir)
        return snapshots[0]["files"] if snapshots else {}

    def _move_to_live(self, rel, src):
        dest = os.path.join(self.live_dir, rel)
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            os.replace(src, dest)                    # keeps the copy time as its mtime
        except OSError:
            self._remove_quietly(src)

    def _discard_pending_locked(self):
        count = len(self._pending)
        for item in self._pending.values():
            self._remove_quietly(item["path"])
        self._pending.clear()
        self._prune_empty_dirs(self.pending_dir)
        return count

    # ------------------------------------------------------------ reading and cleaning
    def list_live(self):
        """{relative_path: {"path": ..., "mtime": ...}} for every TRUSTED copy."""
        result = {}
        if not os.path.isdir(self.live_dir):
            return result
        for dirpath, _dirs, filenames in os.walk(self.live_dir):
            for name in filenames:
                if name.endswith(PART_SUFFIX):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    mtime = os.path.getmtime(full)
                except OSError:
                    continue
                result[os.path.relpath(full, self.live_dir)] = {"path": full, "mtime": mtime}
        return result

    def clear_older_than(self, timestamp):
        """Delete copies made before `timestamp` (a newer snapshot already contains them)."""
        with self._lock:
            for info in self.list_live().values():
                if info["mtime"] < timestamp:
                    self._remove_quietly(info["path"])
            for rel, item in list(self._pending.items()):
                try:
                    mtime = os.path.getmtime(item["path"])
                except OSError:
                    mtime = 0
                if mtime < timestamp:
                    self._remove_quietly(item["path"])
                    del self._pending[rel]
            self._prune_empty_dirs(self.live_dir)
            self._prune_empty_dirs(self.pending_dir)

    def clear(self):
        with self._lock:
            self._pending.clear()
            shutil.rmtree(self.live_dir, ignore_errors=True)
            shutil.rmtree(self.pending_dir, ignore_errors=True)

    # ------------------------------------------------------------ small helpers
    @staticmethod
    def _remove_quietly(path):
        try:
            os.remove(path)
        except OSError:
            pass

    @staticmethod
    def _prune_empty_dirs(root):
        if not os.path.isdir(root):
            return
        for dirpath, _dirs, _files in os.walk(root, topdown=False):
            if dirpath != root:
                try:
                    os.rmdir(dirpath)             # only succeeds if empty
                except OSError:
                    pass
