"""Decoy monitor: bait files that no legitimate program should ever change.

Names start with '!' so they sort FIRST alphabetically (a '~' would sort last).
Touching one (modify / delete / move) is an instant CONFIRMED verdict.
Simply READING one never raises the alarm: file watchers only report changes.
"""
import os
import threading

import config

MARKER = "DO NOT MODIFY - Rewind decoy file. Touching this file triggers an alarm."
MIN_DECOY_BYTES = 4096


def _decoy_text():
    lines, size, n = [], 0, 1
    while size < MIN_DECOY_BYTES:
        line = "Line %04d: %s" % (n, MARKER)
        lines.append(line)
        size += len(line) + 1
        n += 1
    return "\n".join(lines) + "\n"


class DecoyMonitor:
    def __init__(self, directory=None):
        self.directory = os.path.abspath(directory or config.PROTECTED_DIR)
        self._decoys = set()
        self._lock = threading.Lock()

    def plant_decoys(self, root_count=3):
        """Create 3 decoys in the folder itself, plus 1 in each immediate subfolder.

        Returns the sorted list of absolute decoy paths.
        """
        targets = [(self.directory, root_count)]
        for entry in sorted(os.scandir(self.directory), key=lambda e: e.name):
            if entry.is_dir(follow_symlinks=False) and not entry.name.startswith("."):
                targets.append((entry.path, 1))
        number = 1
        for folder, how_many in targets:
            for _ in range(how_many):
                name = "%s%03d.txt" % (config.DECOY_PREFIX, number)
                path = os.path.abspath(os.path.join(folder, name))
                with open(path, "w", encoding="utf-8") as f:
                    f.write(_decoy_text())
                with self._lock:
                    self._decoys.add(path)
                number += 1
        return self.decoys

    @property
    def decoys(self):
        with self._lock:
            return sorted(self._decoys)

    def is_decoy(self, path):
        with self._lock:
            return os.path.abspath(path) in self._decoys

    def was_decoy_touched(self, event):
        """True if the event modified, deleted or moved a decoy (or moved a file onto one)."""
        if event.event_type not in ("modified", "deleted", "moved"):
            return False
        paths = [event.path]
        if event.dest_path:
            paths.append(event.dest_path)
        return any(self.is_decoy(p) for p in paths)
