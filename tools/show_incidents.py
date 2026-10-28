"""Show the incident table from rewind.db in plain lines. Run: rsudo python3 tools/show_incidents.py"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import get_all_incidents  # noqa: E402


def main():
    rows = get_all_incidents()
    if not rows:
        print("No incidents recorded.")
        return
    for row in rows:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["timestamp"]))
        restored = [f for f in row["restored_files"].split(",") if f]
        print("#%d  %s  pid=%s  signals=%s  killed=%s  restored=%d files  status=%s  verified=%s"
              % (row["id"], when, row["attacker_pid"], row["signals"] or "-",
                 row["killed_pids"] or "-", len(restored), row["status"],
                 "yes" if row["verified"] else "NO"))


if __name__ == "__main__":
    main()
