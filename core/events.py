"""Shared data shapes used by every part of Rewind.

FileEvent = "something happened to a file" (who, what, when).
Verdict   = the detection engine's judgement: CLEAN, SUSPICIOUS or CONFIRMED.
"""
from collections import namedtuple
from dataclasses import dataclass
from typing import Optional

import config

# Verdict levels
CLEAN = "CLEAN"
SUSPICIOUS = "SUSPICIOUS"
CONFIRMED = "CONFIRMED"

# Event types
CREATED = "created"
MODIFIED = "modified"
DELETED = "deleted"
MOVED = "moved"


@dataclass(frozen=True)
class FileEvent:
    path: str                       # absolute path of the file that changed
    event_type: str                 # created | modified | deleted | moved
    timestamp: float                # when it happened (seconds)
    pid: int = config.UNATTRIBUTED_PID   # which process did it (-1 = unknown)
    dest_path: Optional[str] = None      # for 'moved': where the file went


# level   : "CLEAN" / "SUSPICIOUS" / "CONFIRMED"
# signals : list such as ["SPEED", "ENTROPY"]
# details : dict of numbers/paths used only for logging (so every verdict is explainable)
Verdict = namedtuple("Verdict", ["level", "signals", "details"])
