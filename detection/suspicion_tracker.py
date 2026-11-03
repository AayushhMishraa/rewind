"""Suspicion tracker: has something been SUSPICIOUS for a long time without a break?

Catches slow or low-noise attackers that only ever trip one signal.
  - note(actor, now)           -> "this actor was suspicious right now"
  - is_sustained(actor, now)   -> True after 3 seconds of unbroken suspicion
A pause LONGER than 2 seconds resets the timer (a pause of exactly 2s does not).
"""
import threading

import config


class SuspicionTracker:
    def __init__(self, sustained_seconds=None, gap_seconds=None, slow_files=None,
                 slow_window=None, slow_min_age=None):
        self.sustained = (config.SUSTAINED_SUSPICION_SECONDS
                          if sustained_seconds is None else sustained_seconds)
        self.gap = (config.SUSPICION_GAP_RESET_SECONDS
                    if gap_seconds is None else gap_seconds)
        self._state = {}               # actor -> [first_suspicious_time, last_suspicious_time]
        self._lock = threading.Lock()
        self.slow_files = config.SLOW_BURN_FILES if slow_files is None else slow_files
        self.slow_window = (config.SLOW_BURN_WINDOW_SECONDS
                            if slow_window is None else slow_window)
        self.slow_min_age = (config.SLOW_BURN_MIN_AGE_SECONDS
                             if slow_min_age is None else slow_min_age)
        self._noise = {}               # path -> time it FIRST turned to noise

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
                self._noise.clear()
            else:
                self._state.pop(actor, None)

    # ---- slow-burn rule (Step 7): a few files turning to noise over a long time ----
    def note_noise(self, path, now):
        """A file that WAS readable just turned into noise (the ENTROPY signal fired)."""
        with self._lock:
            self._noise.setdefault(path, now)      # keep the FIRST time this file went noisy
            self._prune_noise(now)

    def noise_count(self, now):
        """How many distinct files turned to noise within the window."""
        with self._lock:
            self._prune_noise(now)
            return len(self._noise)

    def slow_burn(self, now):
        """True once enough DISTINCT files turned to noise inside the window AND the oldest of
        them has been noise for a few seconds. Unlike the 'sustained' rule, a pause between
        files does NOT reset this, so an attacker that stays under the speed limit is still
        caught. The age condition leaves fast attackers to the SPEED / SUSTAINED rules."""
        with self._lock:
            self._prune_noise(now)
            if len(self._noise) < self.slow_files:
                return False
            return now - min(self._noise.values()) >= self.slow_min_age

    def _prune_noise(self, now):
        cutoff = now - self.slow_window
        for path in [p for p, t in self._noise.items() if t < cutoff]:
            del self._noise[path]
