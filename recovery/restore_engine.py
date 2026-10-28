"""Restore engine: put the protected folder back the way it was.

Steps:
1. Pick the newest snapshot that (a) was FINISHED before the attack began
     (minus a 1-second safety margin) and (b) is not 'poisoned'
     (> 20% of its files look like noise).
2. Inside the watcher pause: copy each file back (via a temp name + atomic
     rename), but only when it is missing or different.
3. Overlay newer 'last known good' copies (your legitimate recent edits).
4. Verify EVERY file's SHA-256 against its recorded fingerprint.
5. Move alien files created after the attack began (e.g. *.locked) into
     safety_copies/quarantine/<trace_id>/ (moved, never deleted).
6. Rebuild the baseline manifest.
Paths are checked so a tampered manifest can never make us write outside the
protected folder.
"""
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import List, Optional

import config
from core.logger import log, new_trace_id
from recovery.known_good import KnownGoodTracker, looks_clean
from recovery.manifest import sha256_file
from recovery.snapshot_manager import DATA_DIRNAME, list_complete_snapshots
from watcher import watcher_control

DEFAULT_MARGIN_SECONDS = 1.0     # snapshots this close to the first alert are not trusted
DEFAULT_SETTLE_SECONDS = 0.3     # let the filesystem watcher finish reporting our own writes
TMP_SUFFIX = ".rewind_tmp"


@dataclass
class RestoreResult:
    restored: List[str] = field(default_factory=list)     # files that were put back
    failed: List[str] = field(default_factory=list)       # files that could not be restored
    verified: bool = False                                # True only if every file checked out
    snapshot_used: Optional[str] = None
    quarantined: List[str] = field(default_factory=list)  # alien files moved aside
    error: Optional[str] = None


def _is_poisoned(info):
    files = info["files"]
    if not files:
        return False
    noisy = sum(1 for e in files.values()
                if isinstance(e, dict) and e.get("entropy", 0) >= config.ENTROPY_THRESHOLD)
    return noisy / len(files) > config.POISONED_SNAPSHOT_RATIO


def choose_snapshot(attack_started_at, safety_dir, margin):
    """Newest usable snapshot -> (info or None, [(name, reason rejected), ...])."""
    cutoff = attack_started_at - margin
    rejected = []
    for info in list_complete_snapshots(safety_dir):
        if info["completed_at"] >= cutoff:
            rejected.append((info["name"], "finished too close to (or after) the attack"))
            continue
        if _is_poisoned(info):
            rejected.append((info["name"], "poisoned: too many files look like noise"))
            continue
        return info, rejected
    return None, rejected


def _inside(root_real, candidate):
    return candidate == root_real or candidate.startswith(root_real + os.sep)


def _resolve_inside(root, rel):
    """Absolute path of root/rel, or None if it would land outside root."""
    root_real = os.path.realpath(root)
    candidate = os.path.normpath(os.path.join(root_real, rel))
    if not _inside(root_real, candidate):
        return None
    if not _inside(root_real, os.path.realpath(os.path.dirname(candidate))):
        return None
    return candidate


def _build_plan(info, tracker, trace_id):
    """{relative_path: where to copy it from, and the fingerprint it must have}."""
    data_dir = os.path.join(info["path"], DATA_DIRNAME)
    plan = {}
    for rel, entry in info["files"].items():
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        plan[rel] = {"src": _resolve_inside(data_dir, rel), "sha": digest, "origin": "snapshot"}
    for rel, live in tracker.list_live().items():
        if live["mtime"] < info["started_at"]:
            continue                      # the snapshot already has something newer
        if not looks_clean(live["path"]):
            log("live_copy_rejected", incident_trace_id=trace_id, path=rel)
            continue
        plan[rel] = {"src": live["path"], "sha": None, "origin": "live"}
    return plan


def _restore_one(rel, item, protected_dir):
    """Returns 'ok' (already correct), 'restored' or 'failed'."""
    src = item["src"]
    dest = _resolve_inside(protected_dir, rel)
    if src is None or dest is None or os.path.islink(src) or not os.path.isfile(src):
        return "failed"
    if item["origin"] == "snapshot" and not item["sha"]:
        return "failed"
    try:
        src_hash = sha256_file(src)
        expected = item["sha"] or src_hash
        if src_hash != expected:
            return "failed"               # the backup itself was damaged or tampered with
        if os.path.isfile(dest) and not os.path.islink(dest) and sha256_file(dest) == expected:
            return "ok"                   # already identical: leave it alone
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + TMP_SUFFIX
        copier = shutil.copy2 if item["origin"] == "snapshot" else shutil.copyfile
        try:
            copier(src, tmp)
            os.replace(tmp, dest)         # atomic: the file is never half-written
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        return "restored" if sha256_file(dest) == expected else "failed"
    except OSError:
        return "failed"


def _quarantine_alien_files(protected_dir, known, cutoff, quarantine_root, result, trace_id):
    for dirpath, dirnames, filenames in os.walk(protected_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in filenames:
            if name.startswith(".") or name.endswith(TMP_SUFFIX):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, protected_dir)
            if rel in known:
                continue
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if max(st.st_mtime, st.st_ctime) < cutoff:
                continue                  # existed before the attack: a legitimate new file
            target = os.path.join(quarantine_root, rel)
            n = 0
            while os.path.exists(target):
                n += 1
                target = os.path.join(quarantine_root, rel) + ".%d" % n
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.move(full, target)
            except OSError:
                continue
            result.quarantined.append(rel)
            log("quarantine_file", incident_trace_id=trace_id, path=rel)


def restore_all(attack_started_at, protected_dir=None, safety_dir=None, manifest=None,
                control=None, trace_id=None, margin_seconds=None, settle_seconds=None):
    """Restore the protected folder. `attack_started_at` is the time of the FIRST alert."""
    protected_dir = os.path.abspath(protected_dir or config.PROTECTED_DIR)
    safety_dir = os.path.abspath(safety_dir or config.SAFETY_DIR)
    control = control or watcher_control.get_default()
    margin = DEFAULT_MARGIN_SECONDS if margin_seconds is None else margin_seconds
    settle = DEFAULT_SETTLE_SECONDS if settle_seconds is None else settle_seconds
    trace_id = trace_id or new_trace_id()
    result = RestoreResult()

    info, rejected = choose_snapshot(attack_started_at, safety_dir, margin)
    for name, why in rejected:
        log("snapshot_rejected", incident_trace_id=trace_id, snapshot=name, reason=why)
    if info is None:
        result.error = "no usable snapshot"
        log("restore_failed", incident_trace_id=trace_id, reason=result.error)
        return result
    result.snapshot_used = info["name"]
    log("restore_start", incident_trace_id=trace_id, snapshot=info["name"])

    with control.paused():                # our own writes must not look like an attack
        tracker = KnownGoodTracker(protected_dir, safety_dir)
        plan = _build_plan(info, tracker, trace_id)
        for rel in sorted(plan):
            status = _restore_one(rel, plan[rel], protected_dir)
            if status == "restored":
                result.restored.append(rel)
                log("restore_file", incident_trace_id=trace_id, path=rel,
                    origin=plan[rel]["origin"])
            elif status == "failed":
                result.failed.append(rel)
                log("restore_file_failed", incident_trace_id=trace_id, path=rel)
        quarantine_root = os.path.join(safety_dir, "quarantine", trace_id)
        _quarantine_alien_files(protected_dir, set(plan), attack_started_at - margin,
                                quarantine_root, result, trace_id)
        if manifest is not None:
            manifest.rebuild()
        if settle > 0:
            time.sleep(settle)

    result.verified = not result.failed
    log("restore_done", incident_trace_id=trace_id, snapshot=info["name"],
        restored=len(result.restored), failed=len(result.failed),
        quarantined=len(result.quarantined), verified=result.verified)
    return result
