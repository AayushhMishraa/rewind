"""Pipeline: connects the parts. Each file event flows through here.

   event -> drop? -> detection (verdict) -> CLEAN       : save a known-good copy
                                          -> SUSPICIOUS : status ELEVATED (backups pause)
                                          -> CONFIRMED  : response engine (kill + restore)

This module only ROUTES. Judging is done by detection/, killing by response/,
restoring by recovery/ (rule R1).

Events are dropped (never judged) when:
- Rewind itself caused them (rule R5)
- the watcher is paused, or the event is older than the last resume (a restore's own writes)
- a response is already running (the response waits for the folder to go quiet)
"""
import os
import threading
import time

import config
from core import logger
from core.activity import ActivityMonitor
from core.events import CLEAN, CREATED, MODIFIED, SUSPICIOUS
from core.state import ELEVATED, RESPONDING, ThreatState
from database import db_manager
from detection.detection_engine import get_confidence
from detection.speed_checker import SpeedChecker
from detection.suspicion_tracker import SuspicionTracker
from recovery.restore_engine import restore_all
from response.response_engine import respond_to_attack
from watcher.watcher_control import WatcherControl

SUSPICIOUS_LOG_INTERVAL = 1.0      # log "still suspicious" at most once per second


def _nothing(message):
    pass


def _real_pid(pid):
    return pid if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0 else None


class Pipeline:
    def __init__(self, *, manifest, decoys, known_good, protected_dir=None, safety_dir=None,
                 state=None, control=None, activity=None, speed=None, tracker=None,
                 respond_fn=None, restore_impl=None, log_incident_fn=None, say=None,
                 async_response=True, calm_seconds=None):
        self.manifest = manifest
        self.decoys = decoys
        self.known_good = known_good
        self.protected_dir = os.path.abspath(protected_dir or config.PROTECTED_DIR)
        self.safety_dir = os.path.abspath(safety_dir or config.SAFETY_DIR)
        self.state = state or ThreatState()
        self.control = control or WatcherControl()
        self.activity = activity or ActivityMonitor()
        self.speed = speed or SpeedChecker()
        self.tracker = tracker or SuspicionTracker()
        self.respond_fn = respond_fn or respond_to_attack
        self.restore_impl = restore_impl or restore_all
        self.log_incident_fn = log_incident_fn or db_manager.log_incident
        self.say = say or _nothing
        self.async_response = async_response
        self.calm_seconds = (config.ELEVATED_CALM_SECONDS
                             if calm_seconds is None else calm_seconds)
        self.events_seen = 0
        self.events_dropped = 0
        self.incidents_handled = 0
        self._last_suspicious = None
        self._last_suspicious_log = 0.0
        self._announced = False
        self._confirm_lock = threading.Lock()
        self._response_thread = None

    # ----- the main entry point (called by the file watcher) -----
    def handle_event(self, event):
        """Judge one FileEvent. Returns the Verdict, or None if the event was dropped."""
        self.events_seen += 1
        self.activity.touch(event.timestamp)          # the response waits on this clock
        if event.pid == os.getpid():                  # R5: never react to our own activity
            self.events_dropped += 1
            return None
        if self.control.should_drop(event.timestamp):
            self.events_dropped += 1
            return None
        if self.state.state == RESPONDING:
            self.events_dropped += 1
            return None
        self.tick(event.timestamp)
        verdict = get_confidence(event, self.speed, self.manifest, self.tracker, self.decoys)
        if verdict.level == CLEAN:
            if event.event_type in (CREATED, MODIFIED):
                self.known_good.track(event.path, event.timestamp)
        elif verdict.level == SUSPICIOUS:
            self.known_good.note_alert(event.timestamp)   # untrusted copies are discarded
            self._on_suspicious(event, verdict)
        else:
            self.known_good.note_alert(event.timestamp)   # (before the response restores)
            self._on_confirmed(event, verdict)
        return verdict

    def tick(self, now=None):
        """Housekeeping: after a calm period, ELEVATED goes back to NORMAL (backups resume)."""
        now = time.time() if now is None else now
        if (self.state.state == ELEVATED and self._last_suspicious is not None
                and now - self._last_suspicious >= self.calm_seconds):
            self.state.return_to_normal(now)
            self._last_suspicious = None
            self._announced = False
            logger.log("calmed_down")
            self.say("[WATCH] Things calmed down. Back to normal, backups resume.")

    def status(self):
        return {"state": self.state.state, "protected_files": len(self.manifest),
                "events_seen": self.events_seen, "events_dropped": self.events_dropped,
                "incidents_handled": self.incidents_handled}

    def wait_for_response(self, timeout=None):
        thread = self._response_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout)

    # ----- verdict handlers -----
    def _on_suspicious(self, event, verdict):
        ts = event.timestamp
        self._last_suspicious = ts
        was_normal = self.state.is_normal()
        self.state.raise_elevated(ts)
        if was_normal or not self._announced:
            self._announced = True
            self.say("[WATCH] Suspicious activity (%s) on %s. Backups paused, watching closely."
                     % (",".join(verdict.signals), os.path.basename(event.path)))
        if ts - self._last_suspicious_log >= SUSPICIOUS_LOG_INTERVAL:
            self._last_suspicious_log = ts
            logger.log("verdict_suspicious", signals=verdict.signals,
                       pid=_real_pid(event.pid), path=event.path)

    def _on_confirmed(self, event, verdict):
        ts = event.timestamp
        with self._confirm_lock:
            if self.state.state == RESPONDING:
                return
            self.state.start_responding(ts)
        attack_start = self.state.episode_start or ts
        trace = logger.new_trace_id()
        pid = _real_pid(event.pid)
        logger.log("verdict_confirmed", incident_trace_id=trace, signals=verdict.signals,
                   pid=pid, path=event.path, attack_started_at=attack_start)
        self.say("[ALERT] ATTACK CONFIRMED by %s (process %s). Stopping it now."
                 % (",".join(verdict.signals), pid if pid else "unknown"))
        if self.async_response:
            self._response_thread = threading.Thread(
                target=self._response_job, args=(event, verdict, attack_start, trace),
                name="rewind-response", daemon=True)
            self._response_thread.start()
        else:
            self._response_job(event, verdict, attack_start, trace)

    # ----- the response (runs in its own thread so events keep flowing) -----
    def _make_restore_fn(self, attack_start, trace):
        def restore():
            return self.restore_impl(attack_start, protected_dir=self.protected_dir,
                                     safety_dir=self.safety_dir, manifest=self.manifest,
                                     control=self.control, trace_id=trace)
        return restore

    def _response_job(self, event, verdict, attack_start, trace):
        restore_fn = self._make_restore_fn(attack_start, trace)
        outcome, crashed = None, False
        try:
            outcome = self.respond_fn(
                verdict, event.pid, restore_fn, self.log_incident_fn,
                self.state, activity=self.activity, protected_dir=self.protected_dir,
                trace_id=trace)
        except RuntimeError as err:
            # Rule R2 guard (or any RuntimeError from the response layer): refuse, log, carry on.
            crashed = True       # reuses the crash cleanup, so the state returns to NORMAL
            logger.log("pipeline_response_guard_caught", incident_trace_id=trace,
                       signals=verdict.signals, error=str(err))
            self.say("[ERROR] The response was refused or failed: %s" % err)
        except Exception as err:
            crashed = True
            logger.log("response_crashed", incident_trace_id=trace, signals=verdict.signals,
                       error=str(err))
            self.say("[ERROR] The response crashed: %s" % err)
        if outcome is None and not crashed:
            return                      # another response is already handling things
        # Fresh start: old counts must not leak into the next episode. Detection resumes
        # either way, so if the attack is still going, the next event starts a new response.
        self.speed.reset()
        self.tracker.reset()
        self._last_suspicious = None
        self._announced = False
        self.state.return_to_normal()
        self.incidents_handled += 1
        if outcome is not None:
            result = getattr(outcome, "restore_result", None)
            self.say("[RESPONSE] %s: stopped %d process(es), restored %d file(s), integrity check %s."
                     % (getattr(outcome, "status", "?"),
                        len(getattr(outcome, "killed_pids", []) or []),
                        len(getattr(outcome, "restored_files", []) or []),
                        "passed" if getattr(result, "verified", False) else "NOT passed"))
