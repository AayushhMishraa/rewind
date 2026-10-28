"""Baseline manifest: a fingerprint list of every file in the protected folder.

For each file we store: sha256 (unique fingerprint), size, and baseline entropy.
'Pre-existing file' in the rest of Rewind means 'present in this manifest'.
Dotfiles (like the sandbox marker) and symlinks are ignored.
"""
import hashlib
import os
import threading

import config
from detection.entropy_checker import calculate_entropy


def _sha256_file(path, chunk=65536):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def build_manifest(directory):
    """Scan a folder and return {relative_path: {"sha256", "size", "entropy"}}."""
    directory = os.path.abspath(directory)
    result = {}
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            try:
                entry = {
                    "sha256": _sha256_file(full),
                    "size": os.path.getsize(full),
                    "entropy": calculate_entropy(full),
                }
            except OSError:
                continue  # file vanished mid-scan; skip it
            result[os.path.relpath(full, directory)] = entry
    return result


class Manifest:
    """Thread-safe wrapper around the manifest data."""

    def __init__(self, root=None, data=None):
        self._root = os.path.abspath(root or config.PROTECTED_DIR)
        self._data = dict(data or {})
        self._lock = threading.RLock()

    @property
    def root(self):
        return self._root

    def key_for(self, path):
        """Absolute paths are made relative to the root; relative ones are used as-is."""
        if os.path.isabs(path):
            return os.path.relpath(path, self._root)
        return os.path.normpath(path)

    def contains(self, path):
        with self._lock:
            return self.key_for(path) in self._data

    def get(self, path):
        with self._lock:
            entry = self._data.get(self.key_for(path))
            return dict(entry) if entry else None

    def baseline_entropy(self, path):
        entry = self.get(path)
        return entry["entropy"] if entry else None

    def replace(self, new_data):
        with self._lock:
            self._data = dict(new_data)

    def rebuild(self):
        """Re-scan the folder from disk and replace the stored data."""
        self.replace(build_manifest(self._root))

    def snapshot(self):
        with self._lock:
            return {k: dict(v) for k, v in self._data.items()}

    def paths(self):
        with self._lock:
            return sorted(self._data)

    def __len__(self):
        with self._lock:
            return len(self._data)


# Public name so other modules (restore engine, tools) can fingerprint files too.
sha256_file = _sha256_file
