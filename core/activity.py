"""Activity monitor: remembers WHEN the protected folder last saw a file event.

The response engine uses it to wait until the folder has been silent for a couple
of seconds before restoring (restoring under a running attacker is pointless: it
would just destroy the restored files again). The pipeline (Stage 5) calls
touch() for every event it receives.
"""
import threading
import time


class ActivityMonitor:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._last = None

    def touch(self, timestamp=None):
        """Record that something happened at `timestamp` (default: now)."""
        t = self._clock() if timestamp is None else timestamp
        with self._lock:
            if self._last is None or t > self._last:
                self._last = t

    @property
    def last_event_time(self):
        with self._lock:
            return self._last

    def quiet_for(self, now=None):
        """Seconds since the last event (infinity if nothing has ever happened)."""
        now = self._clock() if now is None else now
        with self._lock:
            if self._last is None:
                return float("inf")
            return max(0.0, now - self._last)
