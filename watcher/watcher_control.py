"""Watcher pause switch.

While Rewind restores files, its own writes would look like an attack, so the
pipeline drops every event while this switch is on. Events that were QUEUED
during the restore and only delivered after it are also dropped: anything
timestamped before the moment we resumed is ignored.

Pauses can be nested; the watcher resumes only when every pause has ended.
"""
import threading
import time
from contextlib import contextmanager


class WatcherControl:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._lock = threading.RLock()
        self._depth = 0
        self._resumed_at = 0.0

    def pause(self):
        with self._lock:
            self._depth += 1

    def resume(self):
        with self._lock:
            if self._depth > 0:
                self._depth -= 1
                if self._depth == 0:
                    self._resumed_at = self._clock()

    def is_paused(self):
        with self._lock:
            return self._depth > 0

    @property
    def resumed_at(self):
        with self._lock:
            return self._resumed_at

    def should_drop(self, event_timestamp):
        """True if an event must be ignored (paused now, or it happened before we resumed)."""
        with self._lock:
            return self._depth > 0 or event_timestamp < self._resumed_at

    @contextmanager
    def paused(self):
        self.pause()
        try:
            yield self
        finally:
            self.resume()


# One shared switch used by the whole program.
_default = WatcherControl()


def get_default():
    return _default


def pause():
    _default.pause()


def resume():
    _default.resume()


def is_paused():
    return _default.is_paused()


def should_drop(event_timestamp):
    return _default.should_drop(event_timestamp)


def paused():
    return _default.paused()
