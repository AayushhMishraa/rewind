#!/usr/bin/env python3
"""Rewind: Detected. Stopped. Undone.

Start it with:   rsudo python3 main.py          (root is needed to see which process
                                                 is touching your files)
Stop it with:    Ctrl+C

Startup order: database -> sandbox check -> decoys -> baseline + first snapshot ->
file watcher -> periodic snapshots. (The dashboard arrives in Stage 6, the optional
network watcher in Stage 7.)
"""
import os
import signal
import sys
import threading
import time

import config
from core import logger
from core.activity import ActivityMonitor
from core.pipeline import Pipeline
from core.state import ThreatState
from database import db_manager
from detection.decoy_monitor import DecoyMonitor
from recovery.known_good import KnownGoodTracker
from recovery.manifest import Manifest
from recovery.snapshot_manager import SnapshotManager
from watcher.file_watcher import FileWatcher
from watcher.watcher_control import WatcherControl


class StartupError(Exception):
    """Rewind cannot start safely; the message says why in plain English."""


def default_say(message):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), message), flush=True)


class RewindApp:
    """Builds every part and wires them together."""

    def __init__(self, protected_dir=None, safety_dir=None, db_path=None, say=None):
        self.protected_dir = os.path.abspath(protected_dir or config.PROTECTED_DIR)
        self.safety_dir = os.path.abspath(safety_dir or config.SAFETY_DIR)
        self.db_path = db_path or config.DB_PATH
        self.say = say or default_say
        self.state = ThreatState()
        self.control = WatcherControl()
        self.activity = ActivityMonitor()
        self.manifest = Manifest(root=self.protected_dir)
        self.known_good = KnownGoodTracker(self.protected_dir, self.safety_dir)
        self.decoys = DecoyMonitor(self.protected_dir)
        self.snapshots = SnapshotManager(
            self.state, manifest=self.manifest, known_good=self.known_good,
            protected_dir=self.protected_dir, safety_dir=self.safety_dir)

        def save_incident(**fields):
            return db_manager.log_incident(db_path=self.db_path, **fields)

        self.pipeline = Pipeline(
            manifest=self.manifest, decoys=self.decoys, known_good=self.known_good,
            protected_dir=self.protected_dir, safety_dir=self.safety_dir, state=self.state,
            control=self.control, activity=self.activity, log_incident_fn=save_incident,
            say=self.say)
        self.watcher = FileWatcher(self.pipeline.handle_event, protected_dir=self.protected_dir,
                                   idle_callback=self.pipeline.tick)

    def start(self, periodic=True):
        """Start protecting. Returns the path of the first snapshot."""
        db_manager.init_db(self.db_path)
        sentinel = os.path.join(self.protected_dir, config.SENTINEL_NAME)
        if not os.path.isfile(sentinel):
            raise StartupError(
                "%s is not a Rewind sandbox (no %s marker). Run first: rsudo python3 generate_samples.py"
                % (self.protected_dir, config.SENTINEL_NAME))
        os.makedirs(self.safety_dir, exist_ok=True)
        self.decoys.plant_decoys()
        self.manifest.rebuild()
        first = self.snapshots.take_snapshot()
        if first is None:
            raise StartupError("could not take the first snapshot (see rewind.log for the reason)")
        self.watcher.start()
        if periodic:
            self.snapshots.start_periodic()
        logger.log("rewind_started", path=self.protected_dir, snapshot=os.path.basename(first))
        return first

    def stop(self):
        self.snapshots.stop()
        self.watcher.stop()
        self.pipeline.wait_for_response(timeout=15)
        logger.log("rewind_stopped")


def main():
    app = RewindApp()
    if os.geteuid() != 0:
        app.say("[WARNING] Not running as root. Rewind may not be able to see which process "
                "is attacking. Start it with: rsudo python3 main.py")
    try:
        first = app.start()
    except StartupError as err:
        print("Rewind could not start: %s" % err)
        return 1
    app.say("Rewind is watching %s" % app.protected_dir)
    app.say("   protected files : %d (decoys: %d)" % (len(app.manifest), len(app.decoys.decoys)))
    app.say("   first snapshot  : %s" % os.path.basename(first))
    app.say("   (wait about 5 seconds before testing an attack). Press Ctrl+C to stop.")

    stop_event = threading.Event()

    def request_stop(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    while not stop_event.wait(0.5):
        pass
    app.say("Stopping Rewind...")
    app.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
