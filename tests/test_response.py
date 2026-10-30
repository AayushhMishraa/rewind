import os
import signal
import subprocess
import sys
import time

import psutil
import pytest

import config
from core.activity import ActivityMonitor
from core.events import CONFIRMED, Verdict
from core.state import NORMAL, RESPONDING, ThreatState
from recovery.restore_engine import RestoreResult
from response.response_engine import (KillReport, SweepResult, choose_target, get_process_tree,
                                      is_protected_pid, kill_process_tree, respond_to_attack,
                                      sweep_for_suspects, wait_for_quiet)

PARENT_CODE = (
    "import subprocess, sys, time\n"
    "for _ in range(2):\n"
    "    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
    "print('ready', flush=True)\n"
    "time.sleep(60)\n")
IDLE_CODE = "import time\nprint('ready', flush=True)\ntime.sleep(60)\n"
BUSY_CODE = "print('ready', flush=True)\nwhile True:\n    pass\n"
OPEN_FILE_CODE = ("import sys, time\nf = open(sys.argv[1], 'w')\n"
                  "print('ready', flush=True)\ntime.sleep(60)\n")


# ---------------- helpers ----------------
@pytest.fixture
def procs():
    spawned = []
    yield spawned
    for p in spawned:
        try:
            for child in psutil.Process(p.pid).children(recursive=True):
                child.kill()
        except Exception:
            pass
        try:
            p.kill()
            p.wait(timeout=5)
        except Exception:
            pass


def spawn(code, procs, *args, cwd=None):
    p = subprocess.Popen([sys.executable, "-c", code, *args], stdout=subprocess.PIPE,
                         text=True, cwd=cwd)
    procs.append(p)
    assert p.stdout.readline().strip() == "ready"
    return p


def gone(pid, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return True
        except psutil.NoSuchProcess:
            return True
        time.sleep(0.05)
    return False


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


# ---------------- activity monitor and quiet waiting ----------------
def test_activity_monitor_reports_quiet_time():
    clk = Clock(100.0)
    mon = ActivityMonitor(clock=clk)
    assert mon.quiet_for() == float("inf")
    mon.touch()
    assert mon.quiet_for(103.0) == 3.0
    mon.touch(90.0)                                   # an older event changes nothing
    assert mon.last_event_time == 100.0
    mon.touch(110.0)
    assert mon.quiet_for(111.0) == 1.0


def test_wait_for_quiet_returns_true_once_things_calm_down():
    clk = Clock(100.0)
    mon = ActivityMonitor(clock=clk)
    mon.touch()
    assert wait_for_quiet(mon, 2, 10, clock=clk, sleep=clk.sleep, poll=0.5) is True
    assert clk.t - 100.0 == 2.0


def test_wait_for_quiet_returns_immediately_if_already_quiet():
    clk = Clock(100.0)
    mon = ActivityMonitor(clock=clk)                  # never touched
    assert wait_for_quiet(mon, 2, 10, clock=clk, sleep=clk.sleep, poll=0.5) is True
    assert clk.t == 100.0


def test_wait_for_quiet_gives_up_if_activity_never_stops():
    clk = Clock(100.0)
    mon = ActivityMonitor(clock=clk)

    def busy_sleep(seconds):
        clk.sleep(seconds)
        mon.touch()                                   # something keeps happening

    mon.touch()
    assert wait_for_quiet(mon, 2, 10, clock=clk, sleep=busy_sleep, poll=0.5) is False
    assert clk.t - 100.0 >= 10.0


# ---------------- protection (R5) ----------------
def test_protected_pids(procs):
    assert is_protected_pid(os.getpid())
    assert is_protected_pid(os.getppid())
    assert is_protected_pid(1) and is_protected_pid(0) and is_protected_pid(-1)
    assert is_protected_pid("*") and is_protected_pid(None) and is_protected_pid(True)
    for ancestor in psutil.Process().parents():
        assert is_protected_pid(ancestor.pid)
    child = spawn(IDLE_CODE, procs)
    assert is_protected_pid(child.pid) is False       # our own children may be stopped


def test_process_tree_of_a_missing_process_is_empty():
    p = subprocess.Popen(["true"])
    p.wait()
    assert get_process_tree(p.pid) == []
    assert get_process_tree(-1) == [] and get_process_tree("*") == []


def test_process_tree_lists_parent_and_all_descendants(procs):
    parent = spawn(PARENT_CODE, procs)
    tree = get_process_tree(parent.pid)
    assert len(tree) == 3 and tree[0].pid == parent.pid


# ---------------- killing ----------------
def test_kill_process_tree_kills_parent_and_both_children(procs):
    parent = spawn(PARENT_CODE, procs)
    tree_pids = sorted(p.pid for p in get_process_tree(parent.pid))
    assert len(tree_pids) == 3
    report = kill_process_tree(parent.pid)
    assert report.killed == tree_pids and report.failed == [] and report.refused is False
    assert parent.wait(timeout=5) == -signal.SIGKILL
    for pid in tree_pids:
        assert gone(pid)


def test_processes_are_frozen_before_they_are_killed(procs, monkeypatch):
    order = []
    real_suspend, real_kill = psutil.Process.suspend, psutil.Process.kill

    def spy_suspend(self):
        order.append(("suspend", self.pid))
        return real_suspend(self)

    def spy_kill(self):
        order.append(("kill", self.pid))
        return real_kill(self)

    monkeypatch.setattr(psutil.Process, "suspend", spy_suspend)
    monkeypatch.setattr(psutil.Process, "kill", spy_kill)
    parent = spawn(PARENT_CODE, procs)
    report = kill_process_tree(parent.pid)
    first_kill = next(i for i, (action, _) in enumerate(order) if action == "kill")
    frozen_before = {pid for action, pid in order[:first_kill] if action == "suspend"}
    assert frozen_before == set(report.killed) and len(frozen_before) == 3


def test_killing_self_or_ancestors_is_refused():
    for target in (os.getpid(), os.getppid()):
        report = kill_process_tree(target)
        assert report.refused is True and report.killed == [] and report.failed == []
    assert psutil.pid_exists(os.getppid())


def test_killing_something_that_is_not_a_real_pid_is_refused():
    for target in ("*", -1, 0, 1, None):
        report = kill_process_tree(target)
        assert report.refused is True and report.killed == []


def test_killing_an_already_dead_process_is_harmless():
    p = subprocess.Popen(["true"])
    p.wait()
    report = kill_process_tree(p.pid)
    assert report.killed == [] and report.failed == [] and report.refused is False


# ---------------- attribution sweep (R4) ----------------
def test_sweep_finds_a_process_holding_a_file_open(tmp_path, procs):
    folder = tmp_path / "protected"
    folder.mkdir()
    victim = spawn(OPEN_FILE_CODE, procs, str(folder / "x.txt"))
    result = sweep_for_suspects(str(folder), sweeps=2, interval=0.05)
    assert result.suspects == [victim.pid]
    assert result.ambiguous is False and result.basis == "open_file"


def test_sweep_refuses_to_guess_when_there_are_too_many_suspects(tmp_path, procs):
    folder = tmp_path / "protected"
    folder.mkdir()
    pids = [spawn(OPEN_FILE_CODE, procs, str(folder / ("f%d.txt" % i))).pid for i in range(4)]
    result = sweep_for_suspects(str(folder), sweeps=2, interval=0.05, max_suspects=3)
    assert result.ambiguous is True and result.suspects == []
    assert sorted(result.candidates) == sorted(pids)


def test_an_idle_process_sitting_in_the_folder_is_not_a_suspect(tmp_path, procs):
    folder = tmp_path / "protected"
    folder.mkdir()
    spawn(IDLE_CODE, procs, cwd=str(folder))          # like a terminal you cd'd into the folder
    result = sweep_for_suspects(str(folder), sweeps=2, interval=0.3)
    assert result.suspects == []


def test_a_busy_process_inside_the_folder_is_a_suspect(tmp_path, procs):
    folder = tmp_path / "protected"
    folder.mkdir()
    busy = spawn(BUSY_CODE, procs, cwd=str(folder))
    result = sweep_for_suspects(str(folder), sweeps=2, interval=0.3)
    assert result.suspects == [busy.pid] and result.basis == "cwd_and_active"


def test_rewind_itself_is_never_a_suspect(tmp_path):
    folder = tmp_path / "protected"
    folder.mkdir()
    with open(folder / "mine.txt", "w"):
        result = sweep_for_suspects(str(folder), sweeps=2, interval=0.05)
    assert os.getpid() not in result.candidates and result.suspects == []


# ---------------- choosing the target ----------------
@pytest.mark.parametrize("pid,signals,details,expected", [
    (1234, ["DECOY"], {}, 1234),
    (1234, ["ENTROPY"], {}, 1234),
    (1234, ["SPEED"], {"speed_actor": 1234}, 1234),
    (500, ["SPEED"], {"speed_actor": "*"}, None),                  # innocent bystander event
    (500, ["SPEED", "SUSTAINED"], {"speed_actor": -1}, None),
    (500, ["SPEED", "ENTROPY"], {"speed_actor": "*"}, 500),        # it wrote the noise itself
    (-1, ["DECOY"], {}, None),
])
def test_choose_target(pid, signals, details, expected):
    assert choose_target(pid, signals, details)[0] == expected


# ---------------- the orchestrator (with fakes, so the logic is exact) ----------------
class Harness:
    def __init__(self, quiet=True, kill_report=None, restore_result=None, sweep_result=None,
                 restore_raises=False, log_raises=False):
        self.clock = Clock()
        self.activity = ActivityMonitor(clock=self.clock)
        self.state = ThreatState()
        self.quiet = quiet
        self.calls, self.logged = [], []
        self._kill_report, self._restore_result = kill_report, restore_result
        self._sweep_result = sweep_result
        self.restore_raises, self.log_raises = restore_raises, log_raises
        if not quiet:
            self.activity.touch()

    def sleep(self, seconds):
        self.clock.sleep(seconds)
        if not self.quiet:
            self.activity.touch()

    def kill(self, pid):
        self.calls.append(("kill", pid))
        return self._kill_report or KillReport(killed=[pid], failed=[])

    def sweep(self, folder):
        self.calls.append(("sweep", folder))
        return self._sweep_result or SweepResult([], False, [], "none")

    def restore(self):
        self.calls.append("restore")
        if self.restore_raises:
            raise RuntimeError("disk exploded")
        return self._restore_result or RestoreResult(
            restored=["a.txt", "b.txt"], verified=True, snapshot_used="snapshot_1")

    def log(self, **fields):
        self.calls.append("log")
        if self.log_raises:
            raise RuntimeError("database locked")
        self.logged.append(fields)
        return 7


def run(h, pid=1234, signals=("DECOY",), details=None, **override):
    kwargs = dict(activity=h.activity, kill_fn=h.kill, sweep_fn=h.sweep, clock=h.clock,
                  sleep_fn=h.sleep, trace_id="t1")
    kwargs.update(override)
    verdict = Verdict(CONFIRMED, list(signals), details or {})
    return respond_to_attack(verdict, pid, h.restore, h.log, h.state, **kwargs)


def test_attack_is_stopped_then_restored_then_logged_in_that_order():
    h = Harness()
    out = run(h)
    assert h.calls == [("kill", 1234), "restore", "log"]
    assert out.status == "RESOLVED" and out.killed_pids == [1234]
    assert out.restored_files == ["a.txt", "b.txt"] and out.incident_id == 7
    row = h.logged[0]
    assert row["pid"] == 1234 and row["signals"] == ["DECOY"]
    assert row["killed_pids"] == [1234] and row["status"] == "RESOLVED"
    assert row["verified"] is True and row["snapshot_used"] == "snapshot_1"
    assert h.state.state == NORMAL


def test_folder_wide_speed_alarm_searches_instead_of_killing_the_event_pid():
    h = Harness(sweep_result=SweepResult([777], False, [777], "open_file"))
    out = run(h, pid=500, signals=("SPEED",), details={"speed_actor": "*"})
    assert h.calls == [("sweep", config.PROTECTED_DIR), ("kill", 777), "restore", "log"]
    assert out.status == "RESOLVED" and out.killed_pids == [777]
    assert h.logged[0]["pid"] == 777


def test_ambiguous_attribution_kills_nobody_but_still_restores_when_quiet():
    h = Harness(sweep_result=SweepResult([], True, [1, 2, 3, 4], "open_file"))
    out = run(h, pid=-1)
    assert h.calls == [("sweep", config.PROTECTED_DIR), "restore", "log"]
    assert out.status == "UNATTRIBUTED_ALERT" and out.killed_pids == []
    assert h.logged[0]["details"]["response"]["sweep"]["ambiguous"] is True
    assert h.logged[0]["pid"] == -1
    assert h.state.state == RESPONDING


def test_unattributed_and_never_quiet_means_still_active_and_no_restore():
    h = Harness(quiet=False, sweep_result=SweepResult([], True, [1, 2, 3, 4], "open_file"))
    out = run(h, pid=-1)
    assert out.status == "STILL_ACTIVE" and "restore" not in h.calls
    assert h.calls[-1] == "log"


def test_a_protected_target_is_refused_and_nothing_is_killed():
    from response.response_engine import kill_process_tree as real_kill
    h = Harness()
    out = run(h, pid=os.getpid(), kill_fn=real_kill)
    assert out.killed_pids == [] and out.status == "UNATTRIBUTED_ALERT"
    assert h.logged[0]["details"]["response"]["kill_refused"] is True
    assert psutil.pid_exists(os.getpid())


def test_survivors_mean_still_active_and_no_restore():
    h = Harness(kill_report=KillReport(killed=[], failed=[1234]))
    out = run(h)
    assert out.status == "STILL_ACTIVE" and "restore" not in h.calls
    assert h.state.state == RESPONDING


def test_folder_that_never_goes_quiet_skips_the_restore():
    h = Harness(quiet=False)
    out = run(h)
    assert h.calls == [("kill", 1234), "log"]
    assert out.status == "STILL_ACTIVE" and out.killed_pids == [1234]
    assert out.quiet is False and h.state.state == RESPONDING


def test_an_unverified_restore_is_partial_and_returns_to_normal():
    bad = RestoreResult(restored=["a.txt"], failed=["b.txt"], verified=False,
                        snapshot_used="snapshot_1")
    h = Harness(restore_result=bad)
    out = run(h)
    assert out.status == "PARTIAL" and h.logged[0]["verified"] is False
    assert h.state.state == NORMAL


def test_a_crashing_restore_is_still_logged_as_partial():
    h = Harness(restore_raises=True)
    out = run(h)
    assert out.status == "PARTIAL" and out.restored_files == []
    assert "disk exploded" in h.logged[0]["details"]["response"]["restore_error"]
    assert h.calls[-1] == "log"


def test_attacker_that_already_exited_is_not_an_error():
    h = Harness(kill_report=KillReport(killed=[], failed=[]))
    out = run(h)
    assert out.status == "RESOLVED" and out.killed_pids == []


def test_a_second_response_cannot_start_while_one_is_running():
    h = Harness()
    inner = {}

    def restore_that_triggers_another_response():
        inner["result"] = run(h, trace_id="t2")
        return RestoreResult(restored=[], verified=True)

    h.restore = restore_that_triggers_another_response
    first = run(h)
    assert first.status == "RESOLVED" and inner["result"] is None
    h2 = Harness()
    assert run(h2) is not None                        # the lock was released afterwards


def test_a_failing_incident_log_does_not_crash_the_response():
    h = Harness(log_raises=True)
    out = run(h)
    assert out.status == "RESOLVED" and out.incident_id is None


def test_real_attacker_process_is_really_killed_end_to_end(tmp_path, procs):
    victim = spawn(OPEN_FILE_CODE, procs, str(tmp_path / "f.txt"))
    h = Harness()
    verdict = Verdict(CONFIRMED, ["DECOY"], {})
    out = respond_to_attack(verdict, victim.pid, h.restore, h.log, h.state,
                            activity=ActivityMonitor(), trace_id="e2e")
    assert out.status == "RESOLVED" and out.killed_pids == [victim.pid]
    assert victim.wait(timeout=5) == -signal.SIGKILL
