import os
import random
import subprocess
import sys

import config
from detection.entropy_checker import calculate_entropy
from generate_samples import make_document_text

SCRIPT = os.path.join(config.BASE_DIR, "test_ransomware", "ransomware_v2.py")
# Repeated on purpose (it also lives in the simulator and in test_known_good_regression.py):
# if anyone changes the key in one place, this test fails and says so.
WEAK_KEY = bytes([0x5A, 0xC3, 0x17, 0x9E])


def make_sandbox(root, n=5):
    """A marked sandbox with n realistic text files. Returns {name: original bytes}."""
    root.mkdir(parents=True, exist_ok=True)
    (root / ".REWIND_SANDBOX").write_text("marker")
    rng = random.Random(21)
    originals = {}
    for i in range(n):
        name = "document_%03d.txt" % i
        data = make_document_text(i, rng).encode("utf-8")
        (root / name).write_bytes(data)
        originals[name] = data
    return originals


def run_v2(box, *args):
    return subprocess.run([sys.executable, SCRIPT, "--target", str(box), "--rate", "1000",
                           "--hold", "0", *args], capture_output=True, text=True, timeout=60)


def test_plain_variant_entropy_above_alarm(tmp_path):
    box = tmp_path / "box"
    originals = make_sandbox(box)
    result = run_v2(box, "--limit", "5")
    assert result.returncode == 0 and "5 files overwritten" in result.stdout
    for name, original in originals.items():
        data = (box / name).read_bytes()
        assert data != original and len(data) == len(original)
        assert calculate_entropy(str(box / name)) >= 7.5      # Rewind's entropy check CAN see it


def test_weak_variant_entropy_below_alarm(tmp_path):
    box = tmp_path / "box"
    originals = make_sandbox(box)
    result = run_v2(box, "--weak", "--limit", "5")
    assert result.returncode == 0 and "weak" in result.stdout
    for name, original in originals.items():
        assert (box / name).read_bytes() != original           # it really did scramble the file
        assert calculate_entropy(str(box / name)) < 7.5        # but it stays under the alarm


def test_weak_variant_uses_the_documented_key(tmp_path):
    box = tmp_path / "box"
    originals = make_sandbox(box)
    assert run_v2(box, "--weak", "--limit", "5").returncode == 0
    for name, original in originals.items():
        expected = bytes(b ^ WEAK_KEY[i % 4] for i, b in enumerate(original))
        assert (box / name).read_bytes() == expected


def test_sandbox_guard_refuses_outside_sandbox(tmp_path):
    box = tmp_path / "not_a_sandbox"                           # no .REWIND_SANDBOX marker
    box.mkdir()
    originals = {}
    for i in range(3):
        name = "precious_%d.txt" % i
        data = make_document_text(i, random.Random(5)).encode("utf-8")
        (box / name).write_bytes(data)
        originals[name] = data
    for flags in ([], ["--weak"]):
        result = run_v2(box, *flags)
        assert result.returncode == 2 and "REFUSING" in result.stdout
        for name, data in originals.items():
            assert (box / name).read_bytes() == data           # zero files modified
