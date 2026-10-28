"""Suspicion tracker: has something been SUSPICIOUS for a long time without a break?

Catches slow or low-noise attackers that only ever trip one signal.
  - note(actor, now)           -> "this actor was suspicious right now"
  - is_sustained(actor, now)   -> True after 3 seconds of unbroken suspicion
A pause LONGER than 2 seconds resets the timer (a pause of exactly 2s does not).
"""
import threading

import config


class SuspicionTracker:
    def __init__(self, sustained_seconds=None, gap_seconds=None):
        self.sustained = (config.SUSTAINED_SUSPICION_SECONDS
                          if sustained_seconds is None else sustained_seconds)
        self.gap = (config.SUSPICION_GAP_RESET_SECONDS
                    if gap_seconds is None else gap_seconds)
        self._state = {}               # actor -> [first_suspicious_time, last_suspicious_time]
        self._lock = threading.Lock()

    def note(self, actor, now):
        with self._lock:
            state = self._state.get(actor)
            if state is None or now - state[1] > self.gap:
                self._state[actor] = [now, now]      # (re)start the stopwatch
            else:
                state[1] = max(state[1], now)

    def is_sustained(self, actor, now):
        with self._lock:
            state = self._state.get(actor)
            if state is None:
                return False
            if now - state[1] > self.gap:            # it went quiet: not "continuous"
                return False
            return now - state[0] >= self.sustained

    def reset(self, actor=None):
        with self._lock:
            if actor is None:
                self._state.clear()
            else:
                self._state.pop(actor, None)
