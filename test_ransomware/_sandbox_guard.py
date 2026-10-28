"""Sandbox guard (rule R7): the test ransomware may ONLY damage a marked sandbox.

A folder is a valid target only if ALL of these hold:
- it is a real folder, not a symlink
- it is not '/', not your home folder, and not a folder that CONTAINS your home folder
- it contains the marker file .REWIND_SANDBOX (a real file, not a symlink)
Every file we then touch must resolve (via realpath) to somewhere inside the folder.
"""
import os

SENTINEL = ".REWIND_SANDBOX"
DECOY_PREFIX = "!DECOY_"


class SandboxViolation(Exception):
    """Raised when a folder is not a safe place for the simulator to run."""


def is_inside(root, path):
    return path == root or path.startswith(root + os.sep)


def validate_target(target):
    """Return the real path of a safe sandbox, or raise SandboxViolation."""
    if not target:
        raise SandboxViolation("no target folder given")
    if os.path.islink(target):
        raise SandboxViolation("%s is a symlink" % target)
    if not os.path.isdir(target):
        raise SandboxViolation("%s is not a folder" % target)
    real = os.path.realpath(target)
    home = os.path.realpath(os.path.expanduser("~"))
    if real == os.sep:
        raise SandboxViolation("refusing to run on the root folder /")
    if real == home:
        raise SandboxViolation("refusing to run on your home folder")
    if is_inside(real, home):
        raise SandboxViolation("%s contains your home folder" % real)
    sentinel = os.path.join(real, SENTINEL)
    if os.path.islink(sentinel) or not os.path.isfile(sentinel):
        raise SandboxViolation("%s has no %s marker file" % (real, SENTINEL))
    return real


def safe_files(target_real, avoid_decoys=False):
    """The files the simulator may touch, in alphabetical order (decoys sort first)."""
    files = []
    for dirpath, dirnames, filenames in os.walk(target_real):      # never follows symlinks
        dirnames[:] = sorted(d for d in dirnames
                             if not d.startswith(".")
                             and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            if avoid_decoys and name.startswith(DECOY_PREFIX):
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            real = os.path.realpath(full)
            if not is_inside(target_real, real):
                continue
            files.append(real)
    return files
