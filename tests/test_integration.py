"""End-to-end tests: the REAL watcher, a REAL attacker process, a REAL kill and restore.

Each test builds its own temporary sandbox, so your real protected_folder is untouched.
"""
import os
import subprocess
import sys
import time
import zipfile

import config
from database import db_manager
from generate_samples import generate
from main import RewindApp
from tools.verify_restore import verify

V1 = os.path.join(config.BASE_DIR, "test_ransomware", "ransomware_v1.py")


def build(tmp_path):
    paths = dict(protected_dir=str(tmp_path / "protected"), safety_dir=str(tmp_path / "safety"),
                 hashes_path=str(tmp_path / "data" / "hashes.json"),
                 db_path=str(tmp_path / "t.db"), log_path=str(tmp_path / "t.log"))
    generate(**paths)
    app = RewindApp(protected_dir=paths["protected_dir"], safety_dir=paths["safety_dir"],
                    db_path=paths["db_path"], say=lambda message: None)
    return paths, app


def wait_for_incident(db_path, timeout=45):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = db_manager.get_all_incidents(db_path)
        if rows:
            return rows
        time.sleep(0.2)
    return []


def run_real_attack(tmp_path, *extra):
    paths, app = build(tmp_path)
    attacker = None
    try:
        app.start(periodic=False)
        time.sleep(1.6)       # restore never trusts a snapshot finished <1 s before an attack
        attacker = subprocess.Popen([sys.executable, V1, "--target", paths["protected_dir"], *extra],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rows = wait_for_incident(paths["db_path"])
        assert rows, "no incident was recorded"
        assert attacker.wait(timeout=10) == -9            # it was killed with SIGKILL
        matched, total, problems, extras = verify(paths["protected_dir"], paths["hashes_path"])
        return rows[0], (matched, total), app
    finally:
        app.stop()
        if attacker is not None and attacker.poll() is None:
            attacker.kill()


def test_scenario_s1a_decoy_path_stops_the_attacker_and_restores_everything(tmp_path):
    row, (matched, total), app = run_real_attack(tmp_path)
    assert "DECOY" in row["signals"]
    assert row["status"] == "RESOLVED" and row["verified"] == 1
    assert (matched, total) == (100, 100)


def test_scenario_s1b_speed_plus_entropy_path_without_decoys(tmp_path):
    row, (matched, total), app = run_real_attack(tmp_path, "--avoid-decoys")
    assert "ENTROPY" in row["signals"] and "SPEED" in row["signals"]
    assert row["status"] == "RESOLVED" and row["verified"] == 1
    assert (matched, total) == (100, 100)


def test_scenario_s3c_a_legitimate_zip_inside_the_folder_raises_no_alarm(tmp_path):
    paths, app = build(tmp_path)
    try:
        app.start(periodic=False)
        time.sleep(0.5)
        with zipfile.ZipFile(os.path.join(paths["protected_dir"], "backup.zip"), "w",
                             zipfile.ZIP_DEFLATED) as z:
            for name in sorted(os.listdir(paths["protected_dir"])):
                if name.startswith("document_"):
                    z.write(os.path.join(paths["protected_dir"], name), name)
        time.sleep(3)
        assert db_manager.get_all_incidents(paths["db_path"]) == []
        assert app.state.state == "NORMAL"
        assert app.pipeline.events_seen > 0                 # it WAS watching
    finally:
        app.stop()


def test_scenario_s3f_a_fast_legitimate_bulk_edit_is_not_treated_as_an_attack(tmp_path):
    paths, app = build(tmp_path)
    try:
        app.start(periodic=False)
        time.sleep(0.5)
        for name in sorted(os.listdir(paths["protected_dir"])):
            if name.startswith("document_"):
                with open(os.path.join(paths["protected_dir"], name), "a") as f:
                    f.write("one more line added by a script\n")
        time.sleep(4)
        assert db_manager.get_all_incidents(paths["db_path"]) == []
        assert app.state.state != "RESPONDING"
    finally:
        app.stop()
