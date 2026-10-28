"""Create (or reset) the Rewind test sandbox.

What it does:
1. Prepares protected_folder/ (REFUSES to wipe a non-empty folder that lacks the
     sandbox marker, a symlink, your home folder, '/', or a folder containing this project)
2. Writes the marker file .REWIND_SANDBOX
3. Creates 100 plain-text files (document_000.txt ... document_099.txt), each >= 8 KB.
     The text is seeded, so every run produces IDENTICAL files.
4. Saves each file's SHA-256 fingerprint to test_data/original_hashes.json
     (an independent reference used later to check restores byte-for-byte)
5. Resets safety_copies/ and (unless --keep-db) the database and log
Run it before every test or demo.
"""
import argparse
import hashlib
import json
import os
import random
import shutil
import sys

import config

WORDS = (
    "the of and to in is that it was for on are as with his they at be this from "
    "have or by one had not but what all were when we there can an your which their "
    "said if do will each about how up out them then she many some so these would "
    "other into has more her two like him see time could no make than first been "
    "its who now people my made over did down only way find use may water long "
    "little very after words called just where most know"
).split()


class SandboxError(Exception):
    """Raised when we refuse to touch a folder because it is not a safe sandbox."""


def make_document_text(index, rng, min_bytes=None):
    """Plain English-like text of at least min_bytes bytes (ASCII only)."""
    min_bytes = min_bytes or config.SAMPLE_MIN_BYTES
    lines = ["Document %03d - placeholder content for Rewind testing" % index, ""]
    size = sum(len(line) + 1 for line in lines)
    while size < min_bytes:
        n_words = rng.randint(8, 16)
        sentence = " ".join(rng.choice(WORDS) for _ in range(n_words)).capitalize() + "."
        lines.append(sentence)
        size += len(sentence) + 1
    return "\n".join(lines) + "\n"


def _wipe_contents(path):
    for entry in os.scandir(path):
        if entry.is_symlink() or entry.is_file():
            os.unlink(entry.path)
        else:
            shutil.rmtree(entry.path)


def _prepare_protected_dir(protected_dir):
    if os.path.islink(protected_dir):
        raise SandboxError("Refusing: %s is a symlink." % protected_dir)
    real = os.path.realpath(protected_dir)
    home = os.path.realpath(os.path.expanduser("~"))
    base = os.path.realpath(config.BASE_DIR)
    if real in (os.sep, home) or os.path.commonpath([real, base]) == real:
        raise SandboxError("Refusing: %s is not a safe sandbox location." % protected_dir)
    if os.path.exists(protected_dir):
        if not os.path.isdir(protected_dir):
            raise SandboxError("Refusing: %s is not a folder." % protected_dir)
        sentinel = os.path.join(protected_dir, config.SENTINEL_NAME)
        has_marker = os.path.isfile(sentinel) and not os.path.islink(sentinel)
        if os.listdir(protected_dir) and not has_marker:
            raise SandboxError(
                "Refusing to wipe %s: it has files but no %s marker. "
                "It might be a real folder." % (protected_dir, config.SENTINEL_NAME)
            )
        _wipe_contents(protected_dir)
    else:
        os.makedirs(protected_dir)


def _reset_dir(path):
    if os.path.islink(path):
        raise SandboxError("Refusing: %s is a symlink." % path)
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path, exist_ok=True)
    if os.listdir(path):
        raise SandboxError(
            "Could not empty %s (some files are probably owned by root). "
            "Run this script with: rsudo python3 generate_samples.py" % path)


def _remove_if_exists(path):
    for candidate in (path, path + "-wal", path + "-shm", path + "-journal"):
        if os.path.exists(candidate):
            os.remove(candidate)


def generate(protected_dir=None, safety_dir=None, hashes_path=None,
             db_path=None, log_path=None, keep_db=False, count=None):
    protected_dir = protected_dir or config.PROTECTED_DIR
    safety_dir = safety_dir or config.SAFETY_DIR
    hashes_path = hashes_path or config.HASHES_PATH
    db_path = db_path or config.DB_PATH
    log_path = log_path or config.LOG_PATH
    count = count or config.SAMPLE_COUNT

    _prepare_protected_dir(protected_dir)
    with open(os.path.join(protected_dir, config.SENTINEL_NAME), "w", encoding="utf-8") as f:
        f.write("This folder is a Rewind test sandbox. Simulators may overwrite files here.\n")

    rng = random.Random(42)  # fixed seed -> identical files every run
    hashes = {}
    for i in range(count):
        name = "document_%03d.txt" % i
        data = make_document_text(i, rng).encode("utf-8")
        with open(os.path.join(protected_dir, name), "wb") as f:
            f.write(data)
        hashes[name] = hashlib.sha256(data).hexdigest()

    os.makedirs(os.path.dirname(hashes_path), exist_ok=True)
    with open(hashes_path, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=2, sort_keys=True)

    _reset_dir(safety_dir)
    if not keep_db:
        _remove_if_exists(db_path)
        _remove_if_exists(log_path)
    return hashes


def main():
    parser = argparse.ArgumentParser(description="Reset the Rewind test sandbox.")
    parser.add_argument("--keep-db", action="store_true",
                        help="keep rewind.db and rewind.log instead of resetting them")
    args = parser.parse_args()
    try:
        hashes = generate(keep_db=args.keep_db)
    except SandboxError as err:
        print("STOPPED:", err)
        sys.exit(1)
    print("Created %d sample files in %s" % (len(hashes), config.PROTECTED_DIR))
    print("Wrote sandbox marker %s" % config.SENTINEL_NAME)
    print("Saved original hashes to %s" % config.HASHES_PATH)
    print("Reset safety_copies/%s" % ("" if args.keep_db else " and the database/log"))


if __name__ == "__main__":
    main()
