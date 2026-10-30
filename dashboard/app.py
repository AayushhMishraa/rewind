#!/usr/bin/env python3
"""Rewind dashboard: a small Flask app to WATCH Rewind and to launch the test attacks.

Start it:   python3 dashboard/app.py      then open http://127.0.0.1:5000
To use the Simulate buttons:
            export REWIND_ALLOW_SIMULATE=1 ; rsudo python3 dashboard/app.py
(root is needed because the sandbox files are created by root, so the simulators must be
able to write to them).

This is a SEPARATE process from main.py, so it cannot see Rewind's in-memory state. It only:
  - reads rewind.db (the incidents) and rewind.log (what Rewind did, step by step)
  - launches the harmless test simulators as subprocesses
It never starts a watcher or main.py, and never kills or restores anything itself.

Pages:  /  status light + simulate buttons    /incidents  live table    /incidents/<id>  timeline
"""
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from flask import Flask, jsonify, render_template, request  # noqa: E402

import config  # noqa: E402
from database import db_manager  # noqa: E402

NORMAL, ELEVATED, RESPONDING, OFFLINE = "NORMAL", "ELEVATED", "RESPONDING", "OFFLINE"
HEARTBEAT_SECONDS = 75          # the snapshot thread logs every 30 s; silence longer than this = offline
LOG_TAIL_BYTES = 400000         # the status light only needs the end of the log
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}

# The ONLY things the Simulate buttons can run (never built from user text).
VARIANTS = {
    "v1": {"label": "Simulate v1 (fast)", "script": "ransomware_v1.py",
           "args": ["--rate", "20", "--hold", "0.04"]},
    "v2": {"label": "Simulate v2 (plain)", "script": "ransomware_v2.py",
           "args": ["--rate", "12", "--hold", "0.04"]},
    "v2weak": {"label": "Simulate v2 --weak", "script": "ransomware_v2.py",
               "args": ["--weak", "--rate", "12", "--hold", "0.04"]},
}

SIGNAL_TEXT = {
    "DECOY": "a bait file nobody should touch was changed",
    "SPEED": "too many different files changed too fast",
    "ENTROPY": "a readable file turned into random-looking noise",
    "SUSTAINED": "one warning sign lasted 3+ seconds without a break",
}


# ------------------------------------------------------------------ small helpers
def fmt_full(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""


def fmt_clock(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "\u2014"


def count_files(folder):
    """Regular, non-hidden files in the protected folder (decoys included)."""
    total = 0
    for _dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        total += sum(1 for n in filenames if not n.startswith("."))
    return total


def _split(text):
    return [part for part in (text or "").split(",") if part]


# ------------------------------------------------------------------ reading the log
def read_log(log_path, tail_bytes=None, trace_id=None):
    """Parsed log records, oldest first. Unreadable lines are skipped; a missing file gives []."""
    records = []
    try:
        with open(log_path, "rb") as f:
            if tail_bytes:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size > tail_bytes:
                    f.seek(size - tail_bytes)
                    f.readline()                       # drop the partial first line
                else:
                    f.seek(0)
            needle = trace_id.encode() if trace_id else None
            for raw in f:
                if needle and needle not in raw:
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if (isinstance(rec, dict) and isinstance(rec.get("action"), str)
                        and isinstance(rec.get("ts"), (int, float))):
                    if trace_id is None or rec.get("incident_trace_id") == trace_id:
                        records.append(rec)
    except OSError:
        return []
    return records


def derive_state(records, now):
    """Work out the status light from the log. Returns (state, since_timestamp_or_None)."""
    last_idx = None
    for i, r in enumerate(records):
        if r["action"] in ("rewind_started", "rewind_stopped"):
            last_idx = i
    if last_idx is not None and records[last_idx]["action"] == "rewind_stopped":
        return OFFLINE, records[last_idx]["ts"]
    heartbeat = any(now - r["ts"] <= HEARTBEAT_SECONDS
                    and (r["action"].startswith("snapshot_") or r["action"] == "rewind_started")
                    for r in records)
    if not heartbeat:
        return OFFLINE, None
    state, since = NORMAL, None
    for r in records[last_idx or 0:]:
        action = r["action"]
        if action in ("verdict_confirmed", "response_start"):
            new = RESPONDING
        elif action == "verdict_suspicious":
            if state == RESPONDING:
                continue
            new = ELEVATED
        elif action in ("response_end", "response_crashed", "calmed_down"):
            new = NORMAL
        else:
            continue
        if new != state:
            state, since = new, r["ts"]
    return state, since


# ------------------------------------------------------------------ reading the database
def present_incident(row):
    """Turn a database row into a plain dict the pages can use."""
    try:
        details = json.loads(row.get("details") or "{}")
    except ValueError:
        details = {}
    response = details.get("response") if isinstance(details, dict) else None
    trace = str(response.get("trace_id") or "") if isinstance(response, dict) else ""
    restored = _split(row["restored_files"])
    return {
        "id": row["id"], "timestamp": row["timestamp"], "time": fmt_full(row["timestamp"]),
        "trace_id": trace, "trace_short": trace[:8], "attacker_pid": row["attacker_pid"],
        "signals": _split(row["signals"]), "killed_pids": _split(row["killed_pids"]),
        "restored_count": len(restored), "restored_files": restored,
        "status": row["status"], "verified": bool(row["verified"]),
        "snapshot_used": row["snapshot_used"] or "",
    }


def load_incidents(db_path):
    """All incidents, newest first. A missing or unreadable database simply means 'none yet'."""
    if not os.path.isfile(db_path):
        return []
    try:
        return [present_incident(row) for row in db_manager.get_all_incidents(db_path)]
    except (sqlite3.Error, OSError):
        return []


# ------------------------------------------------------------------ the timeline (page 3)
def _step(phase, ts, title, detail, state):
    return {"phase": phase, "time": fmt_clock(ts), "title": title, "detail": detail, "state": state}


def build_timeline(incident, records):
    """DETECTED -> RESPONSE -> RESTORE -> VERIFIED, told from this incident's log lines."""
    def of(*names):
        return [r for r in records if r.get("action") in names]

    steps = []
    signals, status = incident["signals"], incident["status"]
    why = "; ".join(SIGNAL_TEXT.get(s, s) for s in signals) or "unknown"

    det = of("verdict_confirmed")                                     # 1. DETECTED
    title = "Attack confirmed (%s)" % (", ".join(signals) or "?")
    if det:
        r = det[0]
        who = ("process %s" % r["pid"]) if r.get("pid") else "an unidentified process"
        what = os.path.basename(str(r.get("path") or "")) or "a protected file"
        steps.append(_step("DETECTED", r["ts"], title,
                           "Why: %s. Triggered by %s on %s." % (why, who, what), "ok"))
    else:
        steps.append(_step("DETECTED", None, title,
                           "Why: %s. (No matching line in rewind.log; it may have been reset.)" % why,
                           "missing"))

    start, kills, refused = of("response_start"), of("kill_report"), of("kill_refused")   # 2. RESPONSE
    sweeps, quiet = of("attribution_sweep"), of("quiet_wait")
    if start or kills or refused or sweeps or quiet:
        killed = sorted({p for r in kills for p in (r.get("killed") or [])})
        failed = sorted({p for r in kills for p in (r.get("failed") or [])})
        parts, state = [], "ok"
        if sweeps:
            sw = sweeps[-1]
            if sw.get("ambiguous"):
                parts.append("The attacker could not be identified for sure (%d candidates), "
                             "so nobody was killed." % len(sw.get("candidates") or []))
                state = "warn"
            else:
                parts.append("The attacker was not directly seen, so Rewind searched and found "
                             "%d suspect(s)." % len(sw.get("suspects") or []))
        if killed:
            parts.append("Froze, then killed process(es) %s." % ", ".join(map(str, killed)))
        elif refused:
            parts.append("A kill was refused because the target was a protected process.")
            state = "warn"
        elif not (sweeps and sweeps[-1].get("ambiguous")):
            parts.append("No running process had to be killed.")
        if failed:
            parts.append("Could not stop: %s." % ", ".join(map(str, failed)))
            state = "warn"
        if quiet:
            if quiet[-1].get("quiet"):
                parts.append("The folder went quiet, so restoring was safe.")
            else:
                parts.append("The folder never went quiet, so the restore was skipped.")
                state = "warn"
        first = (start or kills or refused or sweeps or quiet)[0]
        steps.append(_step("RESPONSE", first["ts"], "Attacker stopped", " ".join(parts), state))
    else:
        steps.append(_step("RESPONSE", None, "Attacker stopped",
                           "No matching lines in rewind.log. Database says killed: %s."
                           % (", ".join(incident["killed_pids"]) or "none"), "missing"))

    rstart, rdone = of("restore_start"), of("restore_done")           # 3. RESTORE
    rfail = of("restore_failed", "restore_exception")
    if rstart or rdone or rfail:
        done = rdone[-1] if rdone else {}
        restored_n = done.get("restored", len(of("restore_file")))
        failed_n = done.get("failed", len(of("restore_file_failed")))
        quarantined_n = done.get("quarantined", len(of("quarantine_file")))
        snap = (rstart[0].get("snapshot") if rstart else None) or incident["snapshot_used"] or "?"
        parts = ["Used backup %s." % snap,
                 "Put back %d file(s); %d could not be restored." % (restored_n, failed_n)]
        if quarantined_n:
            parts.append("Moved %d leftover file(s) to quarantine (not deleted)." % quarantined_n)
        if of("snapshot_rejected"):
            parts.append("Skipped %d unsafe backup(s)." % len(of("snapshot_rejected")))
        if rfail:
            parts.append("Restore problem: %s." % (rfail[-1].get("reason") or rfail[-1].get("error")
                                                   or "see rewind.log"))
        state = "ok" if (rdone and not failed_n and not rfail) else "warn"
        steps.append(_step("RESTORE", (rstart or rdone or rfail)[0]["ts"],
                           "Files restored from backup", " ".join(parts), state))
    else:
        steps.append(_step("RESTORE", None, "Files restored from backup",
                           "Restore did not run (final status: %s)." % status, "warn"))

    end = of("response_end")                                          # 4. VERIFIED
    ts = (end or rdone or [{}])[-1].get("ts")
    if incident["verified"]:
        steps.append(_step("VERIFIED", ts, "Integrity check passed",
                           "Every restored file matches its original fingerprint. "
                           "Final status: %s." % status, "ok"))
    else:
        steps.append(_step("VERIFIED", ts, "Integrity check NOT passed",
                           "Not every file could be verified. Final status: %s." % status, "warn"))
    return steps


# ------------------------------------------------------------------ simulate helpers
def sandbox_problem(protected_dir):
    """A plain-English reason why simulating is unsafe or impossible, or None if all is fine."""
    if not os.path.isdir(protected_dir):
        return "The protected folder %s does not exist. Run: rsudo python3 generate_samples.py" % protected_dir
    marker = os.path.join(protected_dir, config.SENTINEL_NAME)
    if os.path.islink(marker) or not os.path.isfile(marker):
        return ("Refusing: %s has no %s marker, so it is not a safe test sandbox. "
                "Run: rsudo python3 generate_samples.py" % (protected_dir, config.SENTINEL_NAME))
    for dirpath, dirnames, filenames in os.walk(protected_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in filenames:
            if not name.startswith(".") and not os.access(os.path.join(dirpath, name), os.W_OK):
                return ("The sandbox files are not writable by this dashboard (they belong to root). "
                        "Restart the dashboard with: rsudo python3 dashboard/app.py")
    return None


def simulate_allowed(cfg):
    if cfg["allow_simulate"] is None:
        return os.environ.get("REWIND_ALLOW_SIMULATE") == "1"
    return bool(cfg["allow_simulate"])


def sim_running(cfg):
    proc = cfg["sim"]
    if proc is None:
        return False
    if proc.poll() is None:
        return True
    cfg["sim"] = None
    return False


# ------------------------------------------------------------------ the app
def create_app(protected_dir=None, db_path=None, log_path=None, allow_simulate=None,
               clock=time.time):
    """Build the Flask app. (The arguments exist so tests can use temporary files.)"""
    app = Flask(__name__, template_folder=os.path.join(HERE, "templates"),
                static_folder=os.path.join(HERE, "static"))
    cfg = {"protected_dir": os.path.abspath(protected_dir or config.PROTECTED_DIR),
           "db_path": db_path or config.DB_PATH, "log_path": log_path or config.LOG_PATH,
           "allow_simulate": allow_simulate, "clock": clock, "sim": None,
           "lock": threading.Lock()}

    def engine_state():
        return derive_state(read_log(cfg["log_path"], tail_bytes=LOG_TAIL_BYTES), cfg["clock"]())

    def build_status():
        state, since = engine_state()
        incidents = load_incidents(cfg["db_path"])
        last = incidents[0] if incidents else None
        folder = cfg["protected_dir"]
        marker = os.path.join(folder, config.SENTINEL_NAME)
        return {
            "state": state, "engine_running": state != OFFLINE,
            "since": fmt_clock(since) if since else None, "protected_folder": folder,
            "sandbox_ok": os.path.isfile(marker) and not os.path.islink(marker),
            "files_watched": count_files(folder) if os.path.isdir(folder) else 0,
            "last_incident": ({"id": last["id"], "time": last["time"], "status": last["status"],
                               "signals": last["signals"]} if last else None),
            "simulate_enabled": simulate_allowed(cfg), "simulator_running": sim_running(cfg),
        }

    def fail(message, code):
        return jsonify(ok=False, error=message), code

    @app.before_request
    def only_local_hosts():
        if request.host.split(":")[0].lower() not in ALLOWED_HOSTS:
            return "Forbidden: this dashboard only answers to localhost.", 403

    @app.route("/")
    def index():
        return render_template("index.html", active="status", variants=VARIANTS)

    @app.route("/incidents")
    def incidents_page():
        return render_template("incidents.html", active="incidents")

    @app.route("/incidents/<int:incident_id>")
    def incident_detail(incident_id):
        incident = next((i for i in load_incidents(cfg["db_path"]) if i["id"] == incident_id), None)
        if incident is None:
            return render_template("incident_detail.html", incident=None, steps=[],
                                   active="incidents"), 404
        records = (read_log(cfg["log_path"], trace_id=incident["trace_id"])
                   if incident["trace_id"] else [])
        return render_template("incident_detail.html", incident=incident,
                               steps=build_timeline(incident, records), active="incidents")

    @app.route("/api/status")
    def api_status():
        return jsonify(build_status())

    @app.route("/api/incidents")
    def api_incidents():
        return jsonify(load_incidents(cfg["db_path"]))

    @app.post("/api/simulate")
    def api_simulate():
        if not simulate_allowed(cfg):
            return fail("Simulation is switched off. Stop the dashboard, run: "
                        "export REWIND_ALLOW_SIMULATE=1  then start it again.", 403)
        if not request.is_json:
            return fail("Send JSON (Content-Type: application/json).", 415)
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        variant = body.get("variant")
        if variant not in VARIANTS:
            return fail("Unknown variant.", 400)
        problem = sandbox_problem(cfg["protected_dir"])
        if problem:
            return fail(problem, 400)
        spec = VARIANTS[variant]
        script = os.path.join(ROOT, "test_ransomware", spec["script"])
        if not os.path.isfile(script):
            return fail("Simulator script not found: %s" % script, 500)
        cmd = [sys.executable, script, "--target", cfg["protected_dir"]] + spec["args"]
        if body.get("avoid_decoys"):
            cmd.append("--avoid-decoys")
        with cfg["lock"]:
            if sim_running(cfg):
                return fail("A simulation is already running. Wait for it to finish.", 409)
            try:
                cfg["sim"] = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.DEVNULL,
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                              start_new_session=True)
            except OSError as err:
                return fail("Could not start the simulator: %s" % err, 500)
            proc = cfg["sim"]
        warning = None
        if engine_state()[0] == OFFLINE:
            warning = ("Rewind does not look like it is running, so nothing will stop this attack. "
                       "Reset the files with: rsudo python3 generate_samples.py")
        return jsonify(ok=True, pid=proc.pid, variant=variant, label=spec["label"], warning=warning)

    return app


def main():
    if os.geteuid() != 0:
        print("Note: not running as root. Viewing works; the Simulate buttons need: rsudo python3 dashboard/app.py")
    print("Rewind dashboard: http://%s:%d   (Ctrl+C to stop)" % (config.DASHBOARD_HOST, config.DASHBOARD_PORT))
    create_app().run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT,
                     debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
