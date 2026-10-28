"""Known-good tracker: keeps the latest CLEAN version of files you legitimately edit.

WHY NOT 'copy on first write': a file watcher only reports a change AFTER it
happened, so copying then would copy the already-damaged file. Instead the
pipeline calls track() only when a change was judged CLEAN, and we copy it
then. A copy that looks like noise is never saved, and never replaces a good one.

Copies live in safety_copies/live/ and are timestamped by when they were copied.
"""
import os
import shutil
import threading

import config
from core.logger import log
from detection.entropy_checker import calculate_entropy

LIVE_DIRNAME = "live"
PART_SUFFIX = ".part"


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
    def __init__(self, protected_dir=None, safety_dir=None):
        self.protected_dir = os.path.abspath(protected_dir or config.PROTECTED_DIR)
        self.safety_dir = os.path.abspath(safety_dir or config.SAFETY_DIR)
        self.live_dir = os.path.join(self.safety_dir, LIVE_DIRNAME)
        self._lock = threading.Lock()

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

    def track(self, path):
        """Save a clean copy of `path`. Returns True if a copy was saved."""
        rel = self._relative(path)
        if rel is None or not os.path.isfile(path):
            return False
        dest = os.path.join(self.live_dir, rel)
        part = dest + PART_SUFFIX
        with self._lock:
            try:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copyfile(path, part)          # new mtime = time of copying
                if not looks_clean(part):            # re-check the COPY, not the original
                    os.remove(part)
                    log("known_good_rejected", path=rel)
                    return False
                os.replace(part, dest)
            except OSError:
                if os.path.exists(part):
                    try:
                        os.remove(part)
                    except OSError:
                        pass
                return False
        return True

    def list_live(self):
        """{relative_path: {"path": ..., "mtime": ...}} for every saved copy."""
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
                    try:
                        os.remove(info["path"])
                    except OSError:
                        pass
            self._prune_empty_dirs()

    def clear(self):
        with self._lock:
            shutil.rmtree(self.live_dir, ignore_errors=True)

    def _prune_empty_dirs(self):
        if not os.path.isdir(self.live_dir):
            return
        for dirpath, _dirs, _files in os.walk(self.live_dir, topdown=False):
            if dirpath != self.live_dir:
                try:
                    os.rmdir(dirpath)             # only succeeds if empty
                except OSError:
                    pass
