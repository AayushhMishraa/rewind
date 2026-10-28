"""Speed checker: is something changing too many different files, too fast?

It counts DISTINCT files per actor (a process id, or "*" for everyone together)
inside a sliding 5-second window. Counting distinct files (not raw events)
matters because one single write often creates several events.

WHY the 'recent' rule: a burst that ended 4 seconds ago must not keep the alarm
alive. The burst has to still be happening (>= 3 files in the last second).
"""
import threading
import time

import config


class SpeedChecker:
    def __init__(self, window_seconds=None, min_distinct_files=None,
                 recent_seconds=None, recent_min_files=None):
        self.window = (config.SPEED_WINDOW_SECONDS
                       if window_seconds is None else window_seconds)
        self.min_files = (config.SPEED_MIN_DISTINCT_FILES
                          if min_distinct_files is None else min_distinct_files)
        self.recent_seconds = (config.SPEED_RECENT_SECONDS
                               if recent_seconds is None else recent_seconds)
        self.recent_min = (config.SPEED_RECENT_MIN_FILES
                           if recent_min_files is None else recent_min_files)
        self._events = {}              # actor -> {path: time it last changed}
        self._lock = threading.Lock()  # events arrive from several threads

    def record_event(self, actor, path, timestamp=None):
        """Remember that `actor` changed `path` at `timestamp`; forget old entries."""
        ts = time.time() if timestamp is None else timestamp
        with self._lock:
            files = self._events.setdefault(actor, {})
            files[path] = ts
            cutoff = ts - self.window
            for old_path in [p for p, t in files.items() if t <= cutoff]:
                del files[old_path]

    def count(self, actor, now=None):
        """How many distinct files `actor` changed inside the window."""
        now = time.time() if now is None else now
        with self._lock:
            files = self._events.get(actor, {})
            return sum(1 for t in files.values() if t > now - self.window)

    def get_score(self, actor, now=None):
        """True if the actor changed >= 25 distinct files in 5s AND is still doing it."""
        now = time.time() if now is None else now
        with self._lock:
            files = self._events.get(actor)
            if not files:
                return False
            total = sum(1 for t in files.values() if t > now - self.window)
            recent = sum(1 for t in files.values() if t > now - self.recent_seconds)
        return total >= self.min_files and recent >= self.recent_min

    def reset(self):
        with self._lock:
            self._events.clear()
