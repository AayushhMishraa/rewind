"""Detection engine: combines the detectors into ONE verdict per file event.

Rules (in order):
  1. Decoy touched                  -> CONFIRMED ["DECOY"]  (no other signal needed)
  2. File not in the baseline       -> CLEAN (brand-new files, like a fresh backup.zip,
                                       never count towards SPEED or ENTROPY)
  3. SPEED and ENTROPY both fire    -> CONFIRMED
  4. Exactly one fires              -> SUSPICIOUS ... unless it has lasted 3+ seconds
                                       without a break -> CONFIRMED + "SUSTAINED"
  5. Nothing fires                  -> CLEAN

RULE R1: this module only JUDGES. It never kills a process, restores a file, or
touches a backup. (A test enforces that it imports nothing from those areas.)
"""
import config
from core.events import CLEAN, CONFIRMED, SUSPICIOUS, Verdict
from detection.entropy_checker import is_suspicious_entropy


def get_confidence(event, speed_checker, manifest, tracker, decoy_monitor):
    """Return a Verdict(level, signals, details) for one FileEvent."""
    ts = event.timestamp
    actor = event.pid
    folder = config.FOLDER_WIDE_ACTOR
    base = {"path": event.path, "event_type": event.event_type, "pid": actor}

    # 1. Decoys: instant, certain.
    if decoy_monitor.was_decoy_touched(event):
        return Verdict(CONFIRMED, ["DECOY"], dict(base, reason="decoy file touched"))

    # 2. Only files that existed in the baseline can raise SPEED or ENTROPY.
    if not manifest.contains(event.path):
        return Verdict(CLEAN, [], dict(base, reason="not in baseline manifest"))

    # 3. SPEED: counted per process AND folder-wide (this survives unknown or split PIDs).
    speed_checker.record_event(actor, event.path, ts)
    speed_checker.record_event(folder, event.path, ts)
    speed_actor = None
    if speed_checker.get_score(actor, ts):
        speed_actor = actor
    elif speed_checker.get_score(folder, ts):
        speed_actor = folder

    # 4. ENTROPY: only meaningful when a file was written (not deleted or renamed).
    entropy_fired = False
    if event.event_type in ("created", "modified"):
        entropy_fired = is_suspicious_entropy(event.path, manifest)
    if entropy_fired:
        tracker.note_noise(event.path, ts)    # remembered for the slow-burn rule (C.10)

    signals = []
    if speed_actor is not None:
        signals.append("SPEED")
    if entropy_fired:
        signals.append("ENTROPY")

    details = dict(
        base,
        speed_actor=speed_actor,
        distinct_files_actor=speed_checker.count(actor, ts),
        distinct_files_folder=speed_checker.count(folder, ts),
        speed_threshold=config.SPEED_MIN_DISTINCT_FILES,
    )

    if len(signals) == 2:
        return Verdict(CONFIRMED, signals, details)
    if not signals:
        return Verdict(CLEAN, [], details)

    # Exactly one signal: suspicious, and escalate if it just keeps going.
    track_key = speed_actor if speed_actor is not None else actor
    tracker.note(track_key, ts)
    details["tracker_actor"] = track_key
    if tracker.is_sustained(track_key, ts):
        return Verdict(CONFIRMED, signals + ["SUSTAINED"], details)
    # C.10 slow-burn: 3+ distinct files turned to noise within 60 s (a pause does not reset this)
    if entropy_fired and tracker.slow_burn(ts):
        details["noisy_files_in_window"] = tracker.noise_count(ts)
        return Verdict(CONFIRMED, signals + ["SLOW_SUSPICION"], details)
    return Verdict(SUSPICIOUS, signals, details)
