#!/usr/bin/env python3
"""slow_3s: a HARMLESS test tool that imitates SLOW ransomware: one file every 3 seconds.

Each file is overwritten with random bytes (like encryption). The pauses are longer than the
2-second gap that resets the 'sustained suspicion' timer, and the pace stays far below the
speed limit, so ONLY the slow-burn rule (3+ files turned to noise within 60 s) can catch it.
It REFUSES to run anywhere except a marked sandbox (see _sandbox_guard.py).

  --interval SECONDS  time between files (default 3.0)    --limit N       stop after N files
  --hold SECONDS      keep each file open this long       --target PATH   folder to attack
                      after writing it (default 0.5)      --avoid-decoys  skip the !DECOY_ files
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import config                      # noqa: E402
import _sandbox_guard as guard     # noqa: E402


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Harmless slow ransomware simulator.")
    p.add_argument("--target", default=config.PROTECTED_DIR)
    p.add_argument("--interval", type=float, default=3.0)
    p.add_argument("--hold", type=float, default=0.5)
    p.add_argument("--avoid-decoys", action="store_true")
    p.add_argument("--limit", type=int, default=None)
    return p.parse_args(argv)


def overwrite_with_noise(path, hold):
    """Overwrite a file in place with random bytes of the same size; keep it open for `hold` s."""
    with open(path, "r+b") as f:
        size = os.fstat(f.fileno()).st_size
        f.write(os.urandom(size))
        f.flush()
        if hold > 0:
            time.sleep(hold)         # long enough for Rewind to see who has the file open


def main(argv=None):
    args = parse_args(argv)
    if args.interval <= 0:
        print("--interval must be above 0")
        return 2
    try:
        target = guard.validate_target(args.target)
    except guard.SandboxViolation as err:
        print("REFUSING TO RUN: %s" % err)
        return 2
    files = guard.safe_files(target, args.avoid_decoys)
    if args.limit is not None:
        files = files[:max(0, args.limit)]
    hold = min(args.hold, args.interval * 0.8)
    print("slow_3s (harmless test tool): one file every %.1f s, %d files in %s"
          % (args.interval, len(files), target), flush=True)
    done = 0
    for path in files:
        started = time.time()
        try:
            overwrite_with_noise(path, hold)
        except OSError as err:
            print("skipped %s: %s" % (os.path.basename(path), err), flush=True)
            continue
        done += 1
        rest = args.interval - (time.time() - started)
        if rest > 0:
            time.sleep(rest)
    print("finished: %d files overwritten" % done, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
