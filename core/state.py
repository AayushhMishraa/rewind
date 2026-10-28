"""ThreatState: Rewind's status light.

NORMAL     = all quiet (backups are allowed)
ELEVATED   = something looks suspicious (backups are paused)
RESPONDING = a confirmed attack is being handled (backups are paused)

'generation' goes up on every alert. A snapshot remembers the number it started
with; if the number changed by the time it finishes, an alert happened mid-copy
and the snapshot is thrown away (rule R6).
"""
import threading
import time

NORMAL = "NORMAL"
ELEVATED = "ELEVATED"
RESPONDING = "RESPONDING"


class ThreatState:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._lock = threading.RLock()
        self._state = NORMAL
        self._episode_start = None     # first moment this episode left NORMAL
        self._last_alert = None
        self._generation = 0

    def _now(self, now):
        return self._clock() if now is None else now

    @property
    def state(self):
        with self._lock:
            return self._state

    def is_normal(self):
        with self._lock:
            return self._state == NORMAL

    @property
    def generation(self):
        with self._lock:
            return self._generation

    @property
    def episode_start(self):
        """When the current alert episode began (None while NORMAL)."""
        with self._lock:
            return self._episode_start

    @property
    def last_alert_time(self):
        with self._lock:
            return self._last_alert

    def seconds_since_alert(self, now=None):
        with self._lock:
            if self._last_alert is None:
                return float("inf")
            return self._now(now) - self._last_alert

    def raise_elevated(self, now=None):
        """Something is SUSPICIOUS."""
        with self._lock:
            t = self._now(now)
            if self._state == NORMAL:
                self._state = ELEVATED
                self._episode_start = t
            self._last_alert = t
            self._generation += 1

    def start_responding(self, now=None):
        """A CONFIRMED attack is being handled."""
        with self._lock:
            t = self._now(now)
            if self._episode_start is None:
                self._episode_start = t
            self._state = RESPONDING
            self._last_alert = t
            self._generation += 1

    def return_to_normal(self, now=None):
        with self._lock:
            t = self._now(now)
            was = self._state
            self._state = NORMAL
            self._episode_start = None
            if was != NORMAL:
                self._last_alert = t    # the snapshot cooldown starts from now
                self._generation += 1
