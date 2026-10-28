"""File watcher: turns what happens in the protected folder into FileEvent objects.

It only OBSERVES (rule R1): it never scores, kills or copies anything.
Flow: watchdog (Linux inotify) -> small queue -> worker thread -> callback(FileEvent)

WHY a queue and a worker thread: finding out WHICH process touched a file means
scanning every process, which is slow. Doing that inside watchdog's own thread
would make events pile up.

KNOWN LIMITATION (from the spec): a process that opens and closes a file faster than
our scan can slip through attribution. The event then carries pid -1 (unknown), and
the response engine searches for the attacker instead of guessing.
"""
import os
import queue
import threading
import time

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

import config
from core.events import CREATED, DELETED, MODIFIED, MOVED, FileEvent
from core.logger import log

_PS_ERRORS = (psutil.NoSuchProcess, psutil.AccessDenied, OSError)
IGNORED_SUFFIXES = (".rewind_tmp",)     # Rewind's own temporary files
QUEUE_POLL_SECONDS = 0.25


def _holds_file(proc, target):
    """True if `proc` currently has the file `target` open."""
    try:
        for open_file in proc.open_files():
            if open_file.path == target:
                return True
    except _PS_ERRORS:
        pass
    return False


def get_process_touching_file(filepath, exclude_pids=None, hint_pid=None):
    """Return the psutil.Process that has `filepath` open right now, or None.

    `hint_pid` is checked first (an attacker usually keeps touching file after file,
    so the last culprit is the cheapest guess). Rewind's own PID is never returned.
    """
    target = os.path.realpath(filepath)
    skip = {os.getpid()}
    if exclude_pids:
        skip.update(exclude_pids)
    if hint_pid is not None and hint_pid not in skip:
        try:
            hinted = psutil.Process(hint_pid)
        except (psutil.Error, ValueError, OSError):
            hinted = None
        if hinted is not None and _holds_file(hinted, target):
            return hinted
    for proc in psutil.process_iter():
        if proc.pid in skip:
            continue
        if _holds_file(proc, target):
            return proc
    return None


class _Handler(FileSystemEventHandler):
    def __init__(self, owner):
        super().__init__()
        self._owner = owner

    def on_created(self, event):
        self._owner._enqueue(CREATED, event)

    def on_modified(self, event):
        self._owner._enqueue(MODIFIED, event)

    def on_deleted(self, event):
        self._owner._enqueue(DELETED, event)

    def on_moved(self, event):
        self._owner._enqueue(MOVED, event)


class FileWatcher:
    def __init__(self, callback, protected_dir=None, idle_callback=None,
                 attribute=True, queue_size=50000):
        self.callback = callback
        self.root = os.path.abspath(protected_dir or config.PROTECTED_DIR)
        self.idle_callback = idle_callback      # called every ~0.25 s when nothing is happening
        self.attribute = attribute              # look up which process caused each event?
        self.dropped = 0                        # events lost because the queue was full
        self._queue = queue.Queue(maxsize=queue_size)
        self._stop_flag = threading.Event()
        self._observer = None
        self._worker = None
        self._hint = None

    # ----- public -----
    def start(self):
        if not os.path.isdir(self.root):
            raise FileNotFoundError("protected folder does not exist: %s" % self.root)
        self._stop_flag.clear()
        self._observer = Observer()
        self._observer.schedule(_Handler(self), self.root, recursive=True)
        self._observer.start()
        self._worker = threading.Thread(target=self._run, name="rewind-watcher", daemon=True)
        self._worker.start()
        log("watcher_started", path=self.root)

    def stop(self):
        self._stop_flag.set()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        if self._worker is not None:
            self._worker.join(timeout=5)
            self._worker = None

    # ----- internals -----
    def _ignored(self, path):
        """Dotfiles (like the sandbox marker), anything inside dot-folders, and our temp files."""
        rel = os.path.relpath(path, self.root)
        if rel == "." or rel.startswith(".."):
            return True
        parts = rel.split(os.sep)
        if any(part.startswith(".") for part in parts):
            return True
        return parts[-1].endswith(IGNORED_SUFFIXES)

    def _enqueue(self, event_type, event):
        if event.is_directory:
            return
        stamp = time.time()                       # when it HAPPENED, not when we got to it
        src = os.fsdecode(event.src_path)
        dest = os.fsdecode(event.dest_path) if event_type == MOVED else None
        if event_type == MOVED:
            src_hidden, dest_hidden = self._ignored(src), self._ignored(dest)
            if src_hidden and dest_hidden:
                return
            if src_hidden:
                # e.g. an editor saves via a hidden temp file then renames it onto the
                # real file: from our point of view the real file was just modified.
                event_type, src, dest = MODIFIED, dest, None
            elif dest_hidden:
                dest = None                       # the file moved out of sight
        elif self._ignored(src):
            return
        try:
            self._queue.put_nowait((stamp, event_type, src, dest))
        except queue.Full:
            self.dropped += 1

    def _run(self):
        while not self._stop_flag.is_set():
            try:
                item = self._queue.get(timeout=QUEUE_POLL_SECONDS)
            except queue.Empty:
                if self.idle_callback is not None:
                    try:
                        self.idle_callback()
                    except Exception as err:
                        log("watcher_idle_error", error=str(err))
                continue
            self._process(item)

    def _process(self, item):
        stamp, event_type, src, dest = item
        pid = config.UNATTRIBUTED_PID
        if self.attribute and event_type != DELETED:
            probe = dest or src
            if os.path.exists(probe):
                try:
                    proc = get_process_touching_file(probe, hint_pid=self._hint)
                except Exception:
                    proc = None
                if proc is not None:
                    pid = proc.pid
                    self._hint = pid
        event = FileEvent(path=src, event_type=event_type, timestamp=stamp,
                          pid=pid, dest_path=dest)
        try:
            self.callback(event)
        except Exception as err:                  # the worker thread must never die
            log("watcher_callback_error", error=str(err))


def start_watcher(callback, protected_dir=None, idle_callback=None, attribute=True):
    """Spec-style helper: create a FileWatcher, start it, and return it."""
    watcher = FileWatcher(callback, protected_dir=protected_dir,
                          idle_callback=idle_callback, attribute=attribute)
    watcher.start()
    return watcher
