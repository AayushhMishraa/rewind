"""Entropy checker: did a readable file just turn into random-looking noise?

Shannon entropy runs from 0.0 (totally predictable, like 'AAAA...') to 8.0
(pure random noise, like encrypted data). Plain English text sits around 4.

DESIGN NOTE (rule R1): this detection module must NOT import anything from
'response' or 'recovery'. It receives the baseline manifest as a plain object
and only calls .contains() and .baseline_entropy() on it.
"""
import math
import os
from collections import Counter

import config


def calculate_entropy_bytes(data):
    """Shannon entropy (0.0 to 8.0) of a bytes object."""
    if not data:
        return 0.0
    total = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / total
        entropy -= p * math.log2(p)
    return max(0.0, min(8.0, entropy))


def calculate_entropy(filepath, max_bytes=None):
    """Shannon entropy of a file's first 64 KB (enough to tell text from noise)."""
    limit = max_bytes or config.ENTROPY_SAMPLE_BYTES
    with open(filepath, "rb") as f:
        data = f.read(limit)
    return calculate_entropy_bytes(data)


def is_suspicious_entropy(filepath, manifest):
    """True only if a file that used to be readable has now become noise.

    ALL of these must hold:
1. the file is in the baseline manifest (brand-new files never count)
2. the file is at least ENTROPY_MIN_FILE_BYTES big (tiny files can't reach 7.5)
3. its BASELINE entropy was below ENTROPY_BASELINE_MAX (so already-compressed
         files like zip/jpg/mp3 never trigger)
4. its CURRENT entropy is at least ENTROPY_THRESHOLD
    """
    try:
        if not manifest.contains(filepath):
            return False
        if os.path.getsize(filepath) < config.ENTROPY_MIN_FILE_BYTES:
            return False
        baseline = manifest.baseline_entropy(filepath)
        if baseline is None or baseline >= config.ENTROPY_BASELINE_MAX:
            return False
        return calculate_entropy(filepath) >= config.ENTROPY_THRESHOLD
    except OSError:
        # File vanished or can't be read: not evidence of encryption.
        return False
