"""Response engine: the ONLY part of Rewind allowed to kill processes (rule R1).

It only ever runs after a CONFIRMED verdict (rule R2). Order of events:
1. work out WHO the attacker is (rule R4: never kill without positive attribution)
2. freeze the attacker's whole process tree (SIGSTOP), then kill it (SIGKILL)
3. wait until the folder has been quiet for a few seconds
4. restore the files (restore_fn), then log the incident (log_fn)

Rule R5: Rewind never kills itself, any ancestor of itself (e.g. the shell that
launched it), or PID 1.
"""
import os
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional

import psutil

import config
from core.logger import log, new_trace_id

# Final incident statuses
RESOLVED = "RESOLVED"                      # attacker stopped, files restored and verified
PARTIAL = "PARTIAL"                        # attacker stopped, but restore was incomplete
UNATTRIBUTED_ALERT = "UNATTRIBUTED_ALERT"  # could not positively identify the attacker
STILL_ACTIVE = "STILL_ACTIVE"              # attack not over (survivors or folder never went quiet)

_PS_ERRORS = (psutil.NoSuchProcess, psutil.AccessDenied, OSError)


# ---------------------------------------------------------------- protection (R5)
def _protected_set():
    """PIDs that must never be killed: Rewind itself, every ancestor, and PID 1."""
    protected = {os.getpid(), 1}
    try:
        protected.update(p.pid for p in psutil.Process(os.getpid()).parents())
    except _PS_ERRORS:
        pass
    return protected


def is_protected_pid(pid):
    """True if `pid` must never be killed. Anything that is not a real PID is 'protected'."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return True
    return pid in _protected_set()


# ---------------------------------------------------------------- process trees
def get_process_tree(pid):
    """[process] + all of its descendants. Empty list if the process does not exist."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return []
    try:
        root = psutil.Process(pid)
    except (psutil.NoSuchProcess, ValueError, TypeError):
        return []
    try:
        children = root.children(recursive=True)
    except _PS_ERRORS:
        children = []
    return [root] + children


def _drop_protected(procs):
    protected = _protected_set()
    return [p for p in procs if p.pid > 1 and p.pid not in protected]


def _is_gone(proc):
    """True once a process has really ended (a zombie is already dead)."""
    try:
        if not proc.is_running():
            return True
        return proc.status() == psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return True
    except (psutil.AccessDenied, OSError):
        return False


@dataclass
class KillReport:
    killed: List[int] = field(default_factory=list)   # PIDs confirmed gone
    failed: List[int] = field(default_factory=list)   # PIDs still alive afterwards
    refused: bool = False                             # True if the target was protected
    reason: str = ""


def kill_process_tree(pid, wait_seconds=None, sleep_fn=time.sleep, clock=time.time):
    """Freeze, then kill, a process and all of its descendants.

    Why freeze first (SIGSTOP)? A frozen process cannot spawn new helpers or keep
    encrypting while we work through the list. SIGKILL (not the polite SIGTERM)
    because ransomware could simply ignore a polite request.
    """
    wait = config.KILL_WAIT_SECONDS if wait_seconds is None else wait_seconds
    if is_protected_pid(pid):
        log("kill_refused", pid=pid if isinstance(pid, int) else None,
            reason="protected process or invalid pid")
        return KillReport(refused=True, reason="protected process or invalid pid")

    known = {}

    def freeze(procs):
        for proc in procs:
            if proc.pid in known:
                continue
            known[proc.pid] = proc
            try:
                proc.suspend()
            except _PS_ERRORS:
                pass

    freeze(_drop_protected(get_process_tree(pid)))       # parent first, then descendants
    freeze(_drop_protected(get_process_tree(pid)))       # catch anything spawned meanwhile
    if not known:
        return KillReport()                              # already gone: nothing to do

    for proc in list(known.values()):
        try:
            proc.kill()
        except _PS_ERRORS:
            pass

    deadline = clock() + wait
    while True:
        alive = [p for p in known.values() if not _is_gone(p)]
        if not alive or clock() >= deadline:
            break
        sleep_fn(0.05)

    failed = sorted(p.pid for p in alive)
    killed = sorted(p for p in known if p not in failed)
    log("kill_tree", pid=pid, killed=killed, failed=failed)
    return KillReport(killed=killed, failed=failed)


# ---------------------------------------------------------------- attribution sweep (R4)
@dataclass
class SweepResult:
    suspects: List[int] = field(default_factory=list)    # who we are willing to kill
    ambiguous: bool = False                              # True if too many candidates
    candidates: List[int] = field(default_factory=list)
    basis: str = "none"                                  # why they are suspects


def _is_under(root_real, path):
    return path == root_real or path.startswith(root_real + os.sep)


def _scan_once(root_real):
    """One look at every process: who has a file open in the folder, or sits inside it?"""
    protected = _protected_set()
    found = {}
    for proc in psutil.process_iter():
        pid = proc.pid
        if pid in protected:
            continue
        has_open = False
        cwd_inside = False
        try:
            for f in proc.open_files():
                if _is_under(root_real, f.path):
                    has_open = True
                    break
        except _PS_ERRORS:
            pass
        try:
            cwd_inside = _is_under(root_real, proc.cwd())
        except _PS_ERRORS:
            pass
        if not (has_open or cwd_inside):
            continue
        try:
            times = proc.cpu_times()
            cpu = times.user + times.system
        except _PS_ERRORS:
            cpu = None
        found[pid] = {"open": has_open, "cwd": cwd_inside, "cpu": cpu}
    return found


def sweep_for_suspects(protected_dir=None, sweeps=None, interval=None,
                       max_suspects=None, min_cpu=None, sleep_fn=time.sleep):
    """Look for the attacker a few times over about a second.

    Tier 1: processes with a file open inside the folder.
    Tier 2 (only if tier 1 is empty): processes whose working directory is inside
    the folder AND that are actively using CPU. (An idle terminal that you
    cd'd into the folder is NOT a suspect.)
    If there are more suspects than the limit, we refuse to guess: ambiguous.
    """
    root_real = os.path.realpath(protected_dir or config.PROTECTED_DIR)
    sweeps = config.RESPONSE_SWEEP_COUNT if sweeps is None else sweeps
    interval = config.RESPONSE_SWEEP_INTERVAL if interval is None else interval
    limit = config.MAX_ATTRIBUTION_SWEEP_SUSPECTS if max_suspects is None else max_suspects
    min_cpu = config.SUSPECT_MIN_CPU_SECONDS if min_cpu is None else min_cpu

    merged = {}
    for i in range(max(1, sweeps)):
        for pid, entry in _scan_once(root_real).items():
            m = merged.setdefault(pid, {"open": False, "cwd": False,
                                        "cpu_first": entry["cpu"], "cpu_last": entry["cpu"]})
            m["open"] = m["open"] or entry["open"]
            m["cwd"] = m["cwd"] or entry["cwd"]
            if entry["cpu"] is not None:
                if m["cpu_first"] is None:
                    m["cpu_first"] = entry["cpu"]
                m["cpu_last"] = entry["cpu"]
        if i < sweeps - 1:
            sleep_fn(interval)

    tier1 = sorted(pid for pid, m in merged.items() if m["open"])
    if tier1:
        candidates, basis = tier1, "open_file"
    else:
        candidates = sorted(
            pid for pid, m in merged.items()
            if m["cwd"] and m["cpu_first"] is not None
            and (m["cpu_last"] - m["cpu_first"]) >= min_cpu)
        basis = "cwd_and_active"
    if len(candidates) > limit:
        return SweepResult(suspects=[], ambiguous=True, candidates=candidates, basis=basis)
    return SweepResult(suspects=candidates, ambiguous=False, candidates=candidates,
                       basis=basis if candidates else "none")


def find_suspects(protected_dir=None, **kwargs):
    """Spec-style helper: the list of suspects (empty if none or too ambiguous)."""
    return sweep_for_suspects(protected_dir, **kwargs).suspects


# ---------------------------------------------------------------- waiting for quiet
def wait_for_quiet(activity, quiet_seconds=None, max_wait=None,
                   clock=time.time, sleep=time.sleep, poll=0.1):
    """Wait until the folder has been silent for `quiet_seconds`. False if it never is."""
    quiet_seconds = config.QUIET_PERIOD_SECONDS if quiet_seconds is None else quiet_seconds
    max_wait = config.QUIET_MAX_WAIT_SECONDS if max_wait is None else max_wait
    start = clock()
    while True:
        now = clock()
        if activity.quiet_for(now) >= quiet_seconds - 1e-9:
            return True
        if now - start >= max_wait:
            return False
        sleep(poll)


# ---------------------------------------------------------------- the orchestrator
@dataclass
class ResponseOutcome:
    status: str
    trace_id: str
    target_pid: Optional[int] = None
    killed_pids: List[int] = field(default_factory=list)
    restored_files: List[str] = field(default_factory=list)
    restore_result: object = None
    quiet: bool = False
    incident_id: object = None
    details: dict = field(default_factory=dict)


def choose_target(pid, signals, details):
    """Decide whom to kill. Returns (pid or None, explanation). None means 'search for them'.

    DECOY / ENTROPY: the process that touched the bait or wrote the noise is
    directly observed, so the event's PID is the culprit. SPEED only: the culprit is
    the actor whose count crossed the limit. If that was the folder-wide counter
    (or an unknown actor), the event's PID may be an innocent bystander, so we search.
    """
    details = details or {}
    if "DECOY" in signals or "ENTROPY" in signals:
        culprit, why = pid, "directly observed touching a decoy or writing noise"
    else:
        culprit = details.get("speed_actor")
        if culprit is None:
            culprit = pid
        why = "actor whose speed count crossed the limit"
    if isinstance(culprit, int) and not isinstance(culprit, bool) and culprit > 0:
        return culprit, why
    return None, "attacker not identified (%s)" % why


_response_lock = threading.Lock()


def respond_to_attack(pid, signals, details, restore_fn, log_fn, state, *, activity,
                      protected_dir=None, trace_id=None, kill_fn=None, sweep_fn=None,
                      clock=time.time, sleep_fn=time.sleep):
    """Stop the attacker, wait for quiet, restore, log. ONLY call on a CONFIRMED verdict.

    restore_fn() must return an object with .restored .failed .verified .snapshot_used
    log_fn(**fields) saves the incident (database.db_manager.log_incident fits).
    On RESOLVED / PARTIAL the threat state returns to NORMAL. On STILL_ACTIVE and
    UNATTRIBUTED_ALERT it is left alone: the pipeline decides when it is safe again.
    Returns None if another response is already running.
    """
    if not _response_lock.acquire(blocking=False):
        log("response_skipped", pid=pid if isinstance(pid, int) else None,
            reason="another response is already running")
        return None
    try:
        return _respond(pid, signals, details, restore_fn, log_fn, state, activity,
                        protected_dir, trace_id, kill_fn, sweep_fn, clock, sleep_fn)
    finally:
        _response_lock.release()


def _respond(pid, signals, details, restore_fn, log_fn, state, activity,
             protected_dir, trace_id, kill_fn, sweep_fn, clock, sleep_fn):
    trace = trace_id or new_trace_id()
    kill_fn = kill_fn or kill_process_tree
    sweep_fn = sweep_fn or sweep_for_suspects
    protected_dir = protected_dir or config.PROTECTED_DIR
    signals = list(signals)
    resp = {"trace_id": trace}
    state.start_responding()
    log("response_start", incident_trace_id=trace, signals=signals,
        pid=pid if isinstance(pid, int) else None)

    # ---- 1. who is the attacker? ----
    target, why = choose_target(pid, signals, details)
    resp["target_reason"] = why
    killed, survivors = [], []
    identified = False
    suspects = []

    if target is not None:
        report = kill_fn(target)
        if report.refused:
            resp["kill_refused"] = True
            log("kill_refused", incident_trace_id=trace, signals=signals, pid=target,
                reason=report.reason)
        else:
            identified = True
            killed, survivors = list(report.killed), list(report.failed)
            log("kill_report", incident_trace_id=trace, signals=signals, pid=target,
                killed=killed, failed=survivors)
    else:
        sweep = sweep_fn(protected_dir)
        suspects = list(sweep.suspects)
        resp["sweep"] = {"suspects": suspects, "ambiguous": sweep.ambiguous,
                         "candidates": list(sweep.candidates), "basis": sweep.basis}
        log("attribution_sweep", incident_trace_id=trace, signals=signals, pid=pid,
            suspects=suspects, ambiguous=sweep.ambiguous, candidates=list(sweep.candidates))
        for suspect in suspects:
            report = kill_fn(suspect)
            if report.refused:
                continue
            identified = True
            killed.extend(p for p in report.killed if p not in killed)
            survivors.extend(p for p in report.failed if p not in survivors)
            log("kill_report", incident_trace_id=trace, signals=signals, pid=suspect,
                killed=list(report.killed), failed=list(report.failed))

    resp["target_pid"] = target if target is not None else (suspects[0] if suspects else None)
    resp["survivors"] = survivors

    # ---- 2. wait for quiet, then restore ----
    result = None
    quiet = False
    if survivors:
        status = STILL_ACTIVE                    # we could not stop it: restoring is pointless
    else:
        quiet = wait_for_quiet(activity, clock=clock, sleep=sleep_fn)
        log("quiet_wait", incident_trace_id=trace, signals=signals, quiet=quiet)
        if not quiet:
            status = STILL_ACTIVE                # the folder never went quiet: skip restore
        else:
            try:
                result = restore_fn()
            except Exception as err:             # an incident must still be logged
                resp["restore_error"] = str(err)
                log("restore_exception", incident_trace_id=trace, signals=signals,
                    error=str(err))
            verified = bool(result is not None and result.verified)
            if not identified:
                status = UNATTRIBUTED_ALERT
            elif verified and not survivors:
                status = RESOLVED
            else:
                status = PARTIAL
    resp["quiet"] = quiet

    restored = list(result.restored) if result is not None else []
    verified = bool(result is not None and result.verified)
    snapshot_used = getattr(result, "snapshot_used", None) if result is not None else None
    if result is not None and getattr(result, "error", None):
        resp["restore_error"] = result.error
    full_details = dict(details or {})
    full_details["response"] = resp
    attacker_pid = resp["target_pid"] if resp["target_pid"] is not None else pid

    # ---- 3. record the incident ----
    incident_id = None
    try:
        incident_id = log_fn(pid=attacker_pid, signals=signals, killed_pids=killed,
                             restored_files=restored, status=status, details=full_details,
                             snapshot_used=snapshot_used, verified=verified)
    except Exception as err:
        log("incident_log_failed", incident_trace_id=trace, signals=signals, error=str(err))

    if status in (RESOLVED, PARTIAL):
        state.return_to_normal()
    log("response_end", incident_trace_id=trace, signals=signals, pid=attacker_pid,
        status=status, killed=killed, restored=len(restored), verified=verified)
    return ResponseOutcome(status=status, trace_id=trace, target_pid=resp["target_pid"],
                           killed_pids=killed, restored_files=restored, restore_result=result,
                           quiet=quiet, incident_id=incident_id, details=full_details)
