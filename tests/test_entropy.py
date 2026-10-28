import os
import random

from detection.entropy_checker import (calculate_entropy, calculate_entropy_bytes,
                                       is_suspicious_entropy)
from generate_samples import make_document_text
from recovery.manifest import Manifest, build_manifest


def _text_bytes():
    return make_document_text(0, random.Random(1)).encode("utf-8")  # >= 8 KB of text


def _manifest_for(folder):
    return Manifest(root=str(folder), data=build_manifest(str(folder)))


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def test_plain_text_entropy_is_low(tmp_path):
    p = tmp_path / "a.txt"
    _write(p, _text_bytes())
    assert calculate_entropy(str(p)) < 6.5


def test_random_bytes_entropy_is_high(tmp_path):
    p = tmp_path / "r.bin"
    _write(p, os.urandom(8192))
    assert calculate_entropy(str(p)) >= 7.5


def test_empty_constant_and_uniform_data():
    assert calculate_entropy_bytes(b"") == 0.0
    assert calculate_entropy_bytes(b"A" * 5000) == 0.0
    assert abs(calculate_entropy_bytes(bytes(range(256)) * 32) - 8.0) < 1e-9


def test_readable_file_overwritten_with_noise_is_suspicious(tmp_path):
    p = tmp_path / "doc.txt"
    _write(p, _text_bytes())
    manifest = _manifest_for(tmp_path)
    _write(p, os.urandom(8192))  # simulated encryption
    assert is_suspicious_entropy(str(p), manifest) is True


def test_unchanged_file_is_not_suspicious(tmp_path):
    p = tmp_path / "doc.txt"
    _write(p, _text_bytes())
    manifest = _manifest_for(tmp_path)
    assert is_suspicious_entropy(str(p), manifest) is False


def test_small_files_are_skipped(tmp_path):
    # 4000 random bytes WOULD look like noise (entropy >= 7.5) ...
    p = tmp_path / "mid.txt"
    _write(p, _text_bytes()[:4000])
    manifest = _manifest_for(tmp_path)
    _write(p, os.urandom(4000))
    assert calculate_entropy(str(p)) >= 7.5
    # ... but the file is below the 4096-byte minimum, so it is skipped.
    assert is_suspicious_entropy(str(p), manifest) is False
    # And a tiny 100-byte file is skipped too.
    q = tmp_path / "tiny.txt"
    _write(q, b"hello world " * 8)
    manifest2 = _manifest_for(tmp_path)
    _write(q, os.urandom(100))
    assert is_suspicious_entropy(str(q), manifest2) is False


def test_file_that_was_already_high_entropy_does_not_retrigger(tmp_path):
    p = tmp_path / "archive.bin"  # pretend it is a zip: noisy from the start
    _write(p, os.urandom(8192))
    manifest = _manifest_for(tmp_path)
    _write(p, os.urandom(8192))
    assert is_suspicious_entropy(str(p), manifest) is False


def test_file_not_in_manifest_is_never_flagged(tmp_path):
    manifest = _manifest_for(tmp_path)  # empty folder at this moment
    p = tmp_path / "backup.zip"         # brand-new file appears afterwards
    _write(p, os.urandom(8192))
    assert is_suspicious_entropy(str(p), manifest) is False


def test_missing_file_returns_false(tmp_path):
    manifest = _manifest_for(tmp_path)
    assert is_suspicious_entropy(str(tmp_path / "ghost.txt"), manifest) is False


def test_only_first_64kb_is_read(tmp_path):
    p = tmp_path / "big.bin"
    text = _text_bytes()
    _write(p, (text * 10)[:65536] + os.urandom(65536))
    assert calculate_entropy(str(p)) < 6.5
