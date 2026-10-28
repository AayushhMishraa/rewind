"""Independent restore checker: is every original file back, byte for byte?

Compares protected_folder/ against test_data/original_hashes.json (written by
generate_samples.py). Decoys, dotfiles and extra files are ignored for the score
(extra files are listed as warnings). Exit code 0 = perfect match, 1 = not.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from recovery.manifest import sha256_file  # noqa: E402


def verify(protected_dir, hashes_path):
    """Return (matched, total, problems, extras)."""
    with open(hashes_path, encoding="utf-8") as f:
        expected = json.load(f)
    matched = 0
    problems = []
    for name in sorted(expected):
        path = os.path.join(protected_dir, name)
        if not os.path.isfile(path) or os.path.islink(path):
            problems.append(("MISSING", name))
        elif sha256_file(path) == expected[name]:
            matched += 1
        else:
            problems.append(("CHANGED", name))
    extras = []
    for dirpath, dirnames, filenames in os.walk(protected_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in filenames:
            if name.startswith(".") or name.startswith(config.DECOY_PREFIX):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), protected_dir)
            if rel not in expected:
                extras.append(rel)
    return matched, len(expected), problems, sorted(extras)


def main():
    parser = argparse.ArgumentParser(description="Verify the protected folder against the originals.")
    parser.add_argument("--dir", default=config.PROTECTED_DIR)
    parser.add_argument("--hashes", default=config.HASHES_PATH)
    args = parser.parse_args()
    matched, total, problems, extras = verify(args.dir, args.hashes)
    print("%d/%d match" % (matched, total))
    for kind, name in problems:
        print("  %s: %s" % (kind, name))
    for name in extras:
        print("  warning: extra file not in the original set: %s" % name)
    sys.exit(0 if matched == total else 1)


if __name__ == "__main__":
    main()
