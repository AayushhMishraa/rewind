"""Step 7 tests: the C.10 slow-burn rule, the slow_3s and wiper attackers, and the false-positive cost.

Tests named test_unit_* are fast unit tests. The others run the real Rewind pipeline against real
attacker processes, using the fixtures and helpers from test_acceptance.py.
"""
import os
import random
import shutil
import signal
import subprocess
import sys
import time

import pytest

import config
from core.events import CONFIRMED, SUSPICIOUS, FileEvent
from core.state import NORMAL
from detection.decoy_monitor import DecoyMonitor
from detection.detection_engine import get_confidence
from detection.entropy_checker import calculate_entropy
from detection.speed_checker import SpeedChecker
from detection.suspicion_tracker import SuspicionTracker
from generate_samples import make_document_text
from recovery.manifest import Manifest, build_manifest

try:
    from test_acceptance import (attackers, csv, explain, files_intact, incidents,  # noqa: F401
                                 paths, records, response_finished, rewind, wait_for,
                                 wait_for_incident)
except ImportError:
    from tests.test_acceptance import (attackers, csv, explain, files_intact, incidents,  # noqa: F401
                                       paths, records, response_finished, rewind, wait_for,
                                       wait_for_incident)

SIM_DIR = os.path.join(config.BASE_DIR, "test_ransomware")


# ---------------------------------------------------------------- helpers
def make_world(tmp_path, n=40):
    folder = tmp_path / "protected"
    folder.mkdir()
    rng = random.Random(9)
    for i in range(n):
        (folder / ("document_%03d.txt" % i)).write_bytes(
            make_document_text(i, rng).encode("utf-8"))
    manifest = Manifest(root=str(folder), data=build_manifest(str(folder)))
    return folder, manifest, SpeedChecker(), SuspicionTracker(), DecoyMonitor(str(folder))


def noisy(folder, i):
    """Scramble document i in place (like encryption) and return its path."""
    path = folder / ("document_%03d.txt" % i)
    path.write_bytes(os.urandom(8192))
    return str(path)


def ev(path, t, pid=4242):
    return FileEvent(path=path, event_type="modified", timestamp=t, pid=pid)


def make_sandbox(root, n=4, marker=True):
    root.mkdir(parents=True, exist_ok=True)
    if marker:
        (root / ".REWIND_SANDBOX").write_text("marker")
    rng = random.Random(3)
    originals = {}
    for i in range(n):
        name = "document_%03d.txt" % i
        data = make_document_text(i, rng).encode("utf-8")
        (root / name).write_bytes(data)
        originals[name] = data
    return originals


def run_sim(script, box, *args):
    return subprocess.run([sys.executable, os.path.join(SIM_DIR, script), "--target", str(box),
                           *args], capture_output=True, text=True, timeout=60)


# ---------------------------------------------------------------- C.10 unit tests: the tracker
def test_unit_slow_burn_needs_three_distinct_noisy_files_spread_over_five_seconds():
    tr = SuspicionTracker()
    tr.note_noise("a", 0.0)
    assert tr.slow_burn(0.0) is False
    tr.note_noise("b", 3.0)
    assert tr.slow_burn(3.0) is False                 # only 2 files
    tr.note_noise("c", 6.0)
    assert tr.slow_burn(6.0) is True and tr.noise_count(6.0) == 3


def test_unit_a_fast_burst_is_left_to_the_speed_rules():
    tr = SuspicionTracker()
    for i, name in enumerate("abcd"):
        tr.note_noise(name, i * 0.05)
    assert tr.noise_count(0.2) == 4 and tr.slow_burn(0.2) is False   # many files, but too young
    assert tr.slow_burn(4.9) is False
    assert tr.slow_burn(5.0) is True                  # the fast rules had 5 s and did not fire


def test_unit_the_same_file_turning_to_noise_again_counts_once():
    tr = SuspicionTracker()
    for t in (0.0, 3.0, 6.0, 9.0):
        tr.note_noise("a", t)
    assert tr.noise_count(9.0) == 1 and tr.slow_burn(9.0) is False


def test_unit_old_noisy_files_expire_after_sixty_seconds():
    tr = SuspicionTracker()
    tr.note_noise("a", 0.0)
    tr.note_noise("b", 10.0)
    tr.note_noise("c", 20.0)
    assert tr.slow_burn(20.0) is True
    assert tr.noise_count(65.0) == 2                  # "a" is older than 60 s now
    assert tr.slow_burn(65.0) is False


def test_unit_reset_forgets_the_noise_log():
    tr = SuspicionTracker()
    for i, name in enumerate("abc"):
        tr.note_noise(name, i * 3.0)
    assert tr.slow_burn(6.0) is True
    tr.reset()
    assert tr.noise_count(6.0) == 0 and tr.slow_burn(6.0) is False


# ---------------------------------------------------------------- C.10 unit tests: the engine
def test_unit_engine_confirms_a_slow_attacker_that_the_gap_reset_would_miss(tmp_path):
    folder, manifest, sc, tr, dm = make_world(tmp_path)
    verdicts = [get_confidence(ev(noisy(folder, i), 100 + i * 3.0), sc, manifest, tr, dm)
                for i in range(4)]                    # one file every 3 s
    assert [v.level for v in verdicts[:2]] == [SUSPICIOUS, SUSPICIOUS]
    assert verdicts[0].signals == ["ENTROPY"]
    assert verdicts[2].level == CONFIRMED
    assert verdicts[2].signals == ["ENTROPY", "SLOW_SUSPICION"]
    assert verdicts[2].details["noisy_files_in_window"] == 3
    assert verdicts[3].level == CONFIRMED
    assert "SUSTAINED" not in verdicts[2].signals     # the 2 s gap really did reset that rule
    assert tr.is_sustained(4242, 106.0) is False


def test_unit_engine_a_fast_attack_keeps_its_speed_plus_entropy_verdict(tmp_path):
    folder, manifest, sc, tr, dm = make_world(tmp_path)
    verdicts = [get_confidence(ev(noisy(folder, i), 100 + i * 0.05), sc, manifest, tr, dm)
                for i in range(30)]
    assert [v.level for v in verdicts[:24]] == [SUSPICIOUS] * 24
    assert verdicts[24].level == CONFIRMED and verdicts[24].signals == ["SPEED", "ENTROPY"]
    assert not any("SLOW_SUSPICION" in v.signals for v in verdicts)


def test_unit_engine_one_file_rewritten_slowly_never_reaches_the_slow_burn(tmp_path):
    folder, manifest, sc, tr, dm = make_world(tmp_path)
    verdicts = [get_confidence(ev(noisy(folder, 0), 100 + i * 3.0), sc, manifest, tr, dm)
                for i in range(5)]                    # the SAME file, over and over
    assert all(v.level == SUSPICIOUS for v in verdicts)
    assert not any("SLOW_SUSPICION" in v.signals for v in verdicts)


def test_unit_engine_noisy_files_spread_beyond_sixty_seconds_are_not_confirmed(tmp_path):
    folder, manifest, sc, tr, dm = make_world(tmp_path)
    verdicts = [get_confidence(ev(noisy(folder, i), 100 + i * 40.0), sc, manifest, tr, dm)
                for i in range(3)]
    assert all(v.level == SUSPICIOUS for v in verdicts)


# ---------------------------------------------------------------- the two new simulators
@pytest.mark.parametrize("script,fast_args", [("slow_3s.py", ["--interval", "0.05"]),
                                              ("wiper_v1_zerofill.py", ["--rate", "1000"])])
def test_unit_new_simulators_refuse_to_run_outside_a_sandbox(tmp_path, script, fast_args):
    box = tmp_path / "box"
    originals = make_sandbox(box, marker=False)
    result = run_sim(script, box, *fast_args)
    assert result.returncode == 2 and "REFUSING" in result.stdout
    for name, data in originals.items():
        assert (box / name).read_bytes() == data      # zero files modified


def test_unit_wiper_overwrites_with_zeros_and_honours_the_limit(tmp_path):
    box = tmp_path / "box"
    originals = make_sandbox(box)
    result = run_sim("wiper_v1_zerofill.py", box, "--rate", "1000", "--hold", "0", "--limit", "3")
    assert result.returncode == 0
    zeroed = [n for n, d in originals.items() if (box / n).read_bytes() == bytes(len(d))]
    untouched = [n for n, d in originals.items() if (box / n).read_bytes() == d]
    assert len(zeroed) == 3 and len(untouched) == 1
    assert calculate_entropy(str(box / zeroed[0])) == 0.0   # the opposite of encryption


def test_unit_slow_3s_overwrites_with_noise_and_honours_the_limit(tmp_path):
    box = tmp_path / "box"
    originals = make_sandbox(box)
    result = run_sim("slow_3s.py", box, "--interval", "0.05", "--hold", "0", "--limit", "2")
    assert result.returncode == 0
    changed = [n for n, d in originals.items() if (box / n).read_bytes() != d]
    assert len(changed) == 2
    for name in changed:
        assert calculate_entropy(str(box / name)) >= 7.5


# ---------------------------------------------------------------- live scenarios
def test_c10_slow_3s_attacker_is_caught_by_the_slow_burn_rule(paths, rewind, attackers):
    """One file every 3 s: the 2 s gap rule resets every time, the speed limit is never reached.
    Only the slow-burn rule can confirm it, after the third file."""
    app = rewind()
    attacker = attackers.launch("slow_3s.py", "--avoid-decoys")
    rows = wait_for_incident(paths, timeout=40)
    assert rows, explain(paths, "no incident within 40 s")
    row = rows[0]
    assert attacker.wait(timeout=15) == -signal.SIGKILL
    signals = csv(row["signals"])
    assert "SLOW_SUSPICION" in signals and "ENTROPY" in signals
    assert not ({"SPEED", "SUSTAINED", "DECOY"} & set(signals))
    recs = records(paths)
    suspicious = [r["ts"] for r in recs if r["action"] == "verdict_suspicious"]
    confirmed = [r["ts"] for r in recs if r["action"] == "verdict_confirmed"]
    assert suspicious and confirmed, explain(paths, "expected SUSPICIOUS first, then CONFIRMED")
    assert confirmed[0] - min(suspicious) >= 5.0      # it took the slow path (two 3 s gaps)
    assert row["status"] == "RESOLVED" and row["verified"] == 1
    assert str(attacker.pid) in csv(row["killed_pids"]), explain(paths, "wrong process killed")
    assert 3 <= len(csv(row["restored_files"])) <= 5, explain(paths, "damage was not limited to ~3 files")
    assert response_finished(app), explain(paths, "the response never finished")
    assert files_intact(paths), explain(paths, "files were not restored 100/100")


def test_wiper_zero_fill_is_caught_by_speed_and_sustained_and_restore_is_not_poisoned(
        paths, rewind, attackers):
    """Zeros have entropy 0, so ENTROPY never fires. Speed + sustained must catch it, and the
    restore must bring back the ORIGINAL text (known-good copies must not be poisoned)."""
    app = rewind()
    attacker = attackers.launch("wiper_v1_zerofill.py", "--avoid-decoys", "--rate", "12")
    rows = wait_for_incident(paths)
    assert rows, explain(paths, "no incident within 30 s")
    row = rows[0]
    assert attacker.wait(timeout=15) == -signal.SIGKILL
    signals = csv(row["signals"])
    assert "SPEED" in signals and "SUSTAINED" in signals
    assert "ENTROPY" not in signals and "DECOY" not in signals
    assert row["status"] == "RESOLVED" and row["verified"] == 1
    assert str(attacker.pid) in csv(row["killed_pids"]), explain(paths, "wrong process killed")
    assert len(csv(row["restored_files"])) >= 25, explain(paths, "too few files restored")
    assert response_finished(app), explain(paths, "the response never finished")
    assert files_intact(paths), explain(paths, "files were not restored 100/100")
    sandbox = paths["protected_dir"]
    zeroed = [n for n in os.listdir(sandbox) if n.startswith("document_")
              and calculate_entropy(os.path.join(sandbox, n)) == 0.0]
    assert zeroed == [], "zero-filled files were restored as 'known good': %s" % zeroed[:3]


OPENSSL = ("openssl enc -aes-256-cbc -pbkdf2 -pass pass:secret -in %(f)s -out ../enc.tmp "
           "&& cat ../enc.tmp > %(f)s")


def encrypt_in_place(sandbox, name):
    """A harmless 'legitimate' use: a person encrypts a document with openssl, in place."""
    assert shutil.which("openssl"), "openssl is not installed (sudo apt install openssl)"
    result = subprocess.run(OPENSSL % {"f": name}, shell=True, cwd=sandbox,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_c10_false_positive_cost_quick_encryption_of_three_files_is_only_suspicious(paths, rewind):
    """Measured cost 1: a person encrypting 3 files within seconds is NOT confirmed (the fast
    rules own that case and need 25 files). Rewind notes it as SUSPICIOUS, then calms down."""
    app = rewind()
    for name in ("document_010.txt", "document_011.txt", "document_012.txt"):
        encrypt_in_place(paths["protected_dir"], name)
    time.sleep(3)
    actions = {r["action"] for r in records(paths)}
    assert "verdict_suspicious" in actions, explain(paths, "the noisy files were not even noticed")
    assert "verdict_confirmed" not in actions and "response_start" not in actions
    assert wait_for(lambda: app.state.state == NORMAL, 15), \
        explain(paths, "Rewind never calmed down")
    assert incidents(paths) == []


def test_c10_false_positive_cost_slow_encryption_of_three_files_is_flagged_and_rolled_back(
        paths, rewind):
    """Measured cost 2 (documented): three files encrypted by a person, 5.5 s apart, look exactly
    like a slow attack, so the slow-burn rule CONFIRMS it and the restore rolls them back."""
    app = rewind()
    names = ("document_010.txt", "document_011.txt", "document_012.txt")
    for index, name in enumerate(names):
        encrypt_in_place(paths["protected_dir"], name)
        if index < len(names) - 1:
            time.sleep(5.5)
    rows = wait_for_incident(paths)
    assert rows, explain(paths, "no incident within 30 s")
    row = rows[0]
    signals = csv(row["signals"])
    assert "SLOW_SUSPICION" in signals and "ENTROPY" in signals
    assert csv(row["killed_pids"]) == []              # nothing was left running to kill
    assert row["status"] in ("RESOLVED", "UNATTRIBUTED_ALERT")   # depends on who could be seen
    assert response_finished(app, timeout=30), explain(paths, "the response never finished")
    assert files_intact(paths), explain(paths, "the legitimate files were not rolled back")
