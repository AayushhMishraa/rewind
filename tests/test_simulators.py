import os
import subprocess
import sys

import pytest

import config
from detection.entropy_checker import calculate_entropy
from test_ransomware import _sandbox_guard as guard

SCRIPT = os.path.join(config.BASE_DIR, "test_ransomware", "ransomware_v1.py")
TEXT = b"plain readable text " * 500          # 10,000 bytes


def make_sandbox(root, decoys=True, n=5):
    root.mkdir(parents=True, exist_ok=True)
    (root / ".REWIND_SANDBOX").write_text("marker")
    if decoys:
        for i in (1, 2):
            (root / ("!DECOY_%03d.txt" % i)).write_bytes(TEXT)
    for i in range(n):
        (root / ("document_%03d.txt" % i)).write_bytes(TEXT)
    return root


def run_sim(box, *args):
    return subprocess.run([sys.executable, SCRIPT, "--target", str(box), "--rate", "1000",
                           "--hold", "0", *args], capture_output=True, text=True, timeout=60)


def snapshot_of(box):
    return {p.name: p.read_bytes() for p in box.iterdir() if p.is_file()}


# ---------------- the guard ----------------
def test_a_proper_sandbox_is_accepted(tmp_path):
    box = make_sandbox(tmp_path / "box")
    assert guard.validate_target(str(box)) == os.path.realpath(str(box))


def test_no_marker_means_refusal(tmp_path):
    box = tmp_path / "box"
    box.mkdir()
    with pytest.raises(guard.SandboxViolation):
        guard.validate_target(str(box))


def test_the_root_folder_is_refused():
    with pytest.raises(guard.SandboxViolation):
        guard.validate_target("/")


def test_the_home_folder_is_refused_even_with_a_marker(tmp_path, monkeypatch):
    home = make_sandbox(tmp_path / "home" / "me")
    monkeypatch.setenv("HOME", str(home))
    with pytest.raises(guard.SandboxViolation):
        guard.validate_target(str(home))


def test_a_folder_that_contains_home_is_refused(tmp_path, monkeypatch):
    outer = make_sandbox(tmp_path / "outer")
    home = outer / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    with pytest.raises(guard.SandboxViolation):
        guard.validate_target(str(outer))


def test_a_symlinked_target_is_refused(tmp_path):
    box = make_sandbox(tmp_path / "box")
    link = tmp_path / "link"
    os.symlink(str(box), str(link))
    with pytest.raises(guard.SandboxViolation):
        guard.validate_target(str(link))


def test_missing_paths_and_plain_files_are_refused(tmp_path):
    plain = tmp_path / "file.txt"
    plain.write_text("x")
    for target in (str(tmp_path / "nope"), str(plain), ""):
        with pytest.raises(guard.SandboxViolation):
            guard.validate_target(target)


def test_a_marker_that_is_a_symlink_is_refused(tmp_path):
    box = tmp_path / "box"
    box.mkdir()
    real_marker = tmp_path / "elsewhere"
    real_marker.write_text("x")
    os.symlink(str(real_marker), str(box / ".REWIND_SANDBOX"))
    with pytest.raises(guard.SandboxViolation):
        guard.validate_target(str(box))


# ---------------- which files may be touched ----------------
def test_safe_files_skip_dotfiles_symlinks_and_outside_files(tmp_path):
    box = make_sandbox(tmp_path / "box", decoys=False, n=2)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("keep me")
    os.symlink(str(outside / "secret.txt"), str(box / "link.txt"))
    os.symlink(str(outside), str(box / "linkdir"))
    (box / ".hidden").write_text("x")
    names = [os.path.basename(p) for p in guard.safe_files(os.path.realpath(str(box)))]
    assert names == ["document_000.txt", "document_001.txt"]


def test_decoys_sort_first_and_can_be_avoided(tmp_path):
    box = make_sandbox(tmp_path / "box")
    real = os.path.realpath(str(box))
    with_decoys = [os.path.basename(p) for p in guard.safe_files(real)]
    assert with_decoys[:2] == ["!DECOY_001.txt", "!DECOY_002.txt"]
    without = [os.path.basename(p) for p in guard.safe_files(real, avoid_decoys=True)]
    assert not any(n.startswith("!DECOY_") for n in without) and len(without) == 5


def test_subfolder_files_are_included(tmp_path):
    box = make_sandbox(tmp_path / "box", decoys=False, n=1)
    (box / "sub").mkdir()
    (box / "sub" / "deep.txt").write_bytes(TEXT)
    names = [os.path.relpath(p, os.path.realpath(str(box)))
             for p in guard.safe_files(os.path.realpath(str(box)))]
    assert names == ["document_000.txt", os.path.join("sub", "deep.txt")]


# ---------------- the simulator itself ----------------
def test_the_simulator_refuses_to_run_outside_a_sandbox(tmp_path):
    box = tmp_path / "box"
    box.mkdir()
    (box / "precious.txt").write_bytes(TEXT)
    before = snapshot_of(box)
    result = run_sim(box)
    assert result.returncode == 2 and "REFUSING" in result.stdout
    assert snapshot_of(box) == before


def test_default_run_hits_the_decoys_first(tmp_path):
    box = make_sandbox(tmp_path / "box")
    before = snapshot_of(box)
    result = run_sim(box, "--limit", "3")
    assert result.returncode == 0
    after = snapshot_of(box)
    changed = sorted(n for n in after if after[n] != before[n])
    assert changed == ["!DECOY_001.txt", "!DECOY_002.txt", "document_000.txt"]
    assert all(len(after[n]) == len(before[n]) for n in after)         # same size
    assert calculate_entropy(str(box / "document_000.txt")) >= 7.5     # looks encrypted


def test_avoid_decoys_leaves_the_bait_alone(tmp_path):
    box = make_sandbox(tmp_path / "box")
    before = snapshot_of(box)
    result = run_sim(box, "--avoid-decoys", "--limit", "2")
    assert result.returncode == 0
    after = snapshot_of(box)
    changed = sorted(n for n in after if after[n] != before[n])
    assert changed == ["document_000.txt", "document_001.txt"]


def test_a_bad_rate_is_rejected(tmp_path):
    box = make_sandbox(tmp_path / "box")
    result = subprocess.run([sys.executable, SCRIPT, "--target", str(box), "--rate", "0"],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 2
