"""Show rewind.log as plain lines. Run: python3 tools/show_log.py   (or --tail 100, or --all)"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402

EXTRA_KEYS = ("path", "status", "reason", "snapshot", "killed", "failed", "suspects",
              "restored", "quarantined", "verified", "quiet", "error")


def format_record(rec):
    when = time.strftime("%H:%M:%S", time.localtime(rec.get("ts", 0)))
    parts = [when, rec.get("action", "?")]
    if rec.get("pid") is not None:
        parts.append("pid=%s" % rec["pid"])
    if rec.get("signals"):
        parts.append("signals=%s" % ",".join(rec["signals"]))
    if rec.get("incident_trace_id"):
        parts.append("incident=%s" % rec["incident_trace_id"])
    for key in EXTRA_KEYS:
        if key in rec:
            parts.append("%s=%s" % (key, rec[key]))
    return "  ".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Show rewind.log in plain lines.")
    parser.add_argument("--tail", type=int, default=40)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    if not os.path.isfile(config.LOG_PATH):
        print("No log file yet.")
        return
    with open(config.LOG_PATH, encoding="utf-8") as f:
        lines = f.readlines()
    if not args.all:
        lines = lines[-args.tail:]
    for line in lines:
        try:
            print(format_record(json.loads(line)))
        except ValueError:
            continue


if __name__ == "__main__":
    main()
