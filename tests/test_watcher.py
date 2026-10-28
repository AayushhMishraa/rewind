import os
import subprocess
import sys
import time

import pytest

from core.events import CREATED, DELETED, MODIFIED, MOVED
from watcher.file_watcher import FileWatcher, get_process_touching_file

HOLD_CODE = ("import sys, time\nf = open(sys.argv[1], 'r+b')\n"
             "print('ready', flush=True)\ntime.sleep(60)\n")
WRITER_CODE = ("import sys, time\nf = open(sys.argv[1], 'r+b')\nprint('ready', flush=True)\n"
               "sys.stdin.readline()\nf.write(b'changed content here')\nf.flush()\n"
               "print('written', flush=True)\ntime.sleep(60)\n")


def wait_for(predicate, timeout=6.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def procs():
    spawned = []
    yield spawned
    for p in spawned:
        try:
            p.kill()
            p.wait(timeout=5)
        except Exception:
            pass


@pytest.fixture
def watched(tmp_path):
    folder = tmp_path / "protected"
    folder.mkdir()
    (folder / "sub").mkdir()
    events = []
    watcher = FileWatcher(events.append, protected_dir=str(folder), attribute=False)
    watcher.start()
    time.sleep(0.3)                       # let the filesystem watch settle
    yield folder, events, watcher
    watcher.stop()


# ---------------- which process has a file open? ----------------
def test_finds_the_process_holding_a_file(tmp_path, procs):
    target = tmp_path / "x.txt"
    target.write_bytes(b"data" * 100)
    p = subprocess.Popen([sys.executable, "-c", HOLD_CODE, str(target)],
                         stdout=subprocess.PIPE, text=True)
    procs.append(p)
    assert p.stdout.readline().strip() == "ready"
    found = get_process_touching_file(str(target))
    assert found is not None and found.pid == p.pid


def test_returns_none_when_nobody_has_the_file_open(tmp_path):
    target = tmp_path / "x.txt"
    target.write_bytes(b"data")
    assert get_process_touching_file(str(target)) is None


def test_rewinds_own_pid_is_never_returned(tmp_path):
    target = tmp_path / "x.txt"
    target.write_bytes(b"data")
    with open(target, "r+b"):
        assert get_process_touching_file(str(target)) is None


def test_the_hint_pid_is_checked_first(tmp_path, procs):
    target = tmp_path / "x.txt"
    target.write_bytes(b"data" * 100)
    p = subprocess.Popen([sys.executable, "-c", HOLD_CODE, str(target)],
                         stdout=subprocess.PIPE, text=True)
    procs.append(p)
    assert p.stdout.readline().strip() == "ready"
    found = get_process_touching_file(str(target), hint_pid=p.pid)
    assert found is not None and found.pid == p.pid
    assert get_process_touching_file(str(target), hint_pid=999999) is not None   # bad hint is harmless


# ---------------- the watcher itself ----------------
def test_create_modify_move_and_delete_are_reported(watched):
    folder, events, _ = watched
    a, b = folder / "a.txt", folder / "b.txt"
    a.write_text("hello")
    assert wait_for(lambda: any(e.event_type == CREATED and e.path == str(a) for e in events))
    with open(a, "a") as f:
        f.write(" more")
    assert wait_for(lambda: any(e.event_type == MODIFIED and e.path == str(a) for e in events))
    os.rename(a, b)
    assert wait_for(lambda: any(e.event_type == MOVED and e.path == str(a)
                                and e.dest_path == str(b) for e in events))
    os.remove(b)
    assert wait_for(lambda: any(e.event_type == DELETED and e.path == str(b) for e in events))


def test_events_have_real_timestamps_and_unknown_pid_when_not_attributing(watched):
    folder, events, _ = watched
    before = time.time()
    (folder / "t.txt").write_text("x")
    assert wait_for(lambda: len(events) > 0)
    assert all(before - 1 <= e.timestamp <= time.time() + 1 for e in events)
    assert all(e.pid == -1 for e in events)


def test_files_in_subfolders_are_watched(watched):
    folder, events, _ = watched
    (folder / "sub" / "deep.txt").write_text("x")
    assert wait_for(lambda: any(e.path == str(folder / "sub" / "deep.txt") for e in events))


def test_dotfiles_directories_and_temp_files_are_ignored(watched):
    folder, events, _ = watched
    (folder / ".hidden").write_text("x")
    (folder / "newdir").mkdir()
    (folder / "x.rewind_tmp").write_text("x")
    (folder / "real.txt").write_text("x")
    assert wait_for(lambda: any(e.path.endswith("real.txt") for e in events))
    time.sleep(0.3)
    assert {os.path.basename(e.path) for e in events} == {"real.txt"}


def test_a_hidden_temp_file_renamed_onto_a_real_file_counts_as_a_modification(watched):
    folder, events, _ = watched
    (folder / ".save.tmp").write_text("new content")
    os.replace(folder / ".save.tmp", folder / "target.txt")
    assert wait_for(lambda: any(e.event_type == MODIFIED and e.path == str(folder / "target.txt")
                                for e in events))
    assert not any(".save.tmp" in e.path for e in events)


def test_a_file_moved_out_of_sight_is_reported_without_a_destination(watched):
    folder, events, _ = watched
    (folder / "a.txt").write_text("x")
    assert wait_for(lambda: any(e.event_type == CREATED for e in events))
    os.rename(folder / "a.txt", folder / ".a.bak")
    assert wait_for(lambda: any(e.event_type == MOVED and e.dest_path is None for e in events))


def test_events_are_attributed_to_the_process_holding_the_file(tmp_path, procs):
    folder = tmp_path / "protected"
    folder.mkdir()
    target = folder / "victim.txt"
    target.write_bytes(b"original content " * 10)
    events = []
    watcher = FileWatcher(events.append, protected_dir=str(folder), attribute=True)
    watcher.start()
    time.sleep(0.3)
    p = subprocess.Popen([sys.executable, "-c", WRITER_CODE, str(target)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    procs.append(p)
    try:
        assert p.stdout.readline().strip() == "ready"
        p.stdin.write("go\n")
        p.stdin.flush()
        assert p.stdout.readline().strip() == "written"
        assert wait_for(lambda: any(e.event_type == MODIFIED and e.pid == p.pid for e in events))
    finally:
        watcher.stop()


def test_stopping_the_watcher_ends_its_threads(tmp_path):
    folder = tmp_path / "protected"
    folder.mkdir()
    watcher = FileWatcher(lambda e: None, protected_dir=str(folder), attribute=False)
    watcher.start()
    worker = watcher._worker
    watcher.stop()
    assert not worker.is_alive()


def test_a_missing_folder_is_reported_clearly(tmp_path):
    watcher = FileWatcher(lambda e: None, protected_dir=str(tmp_path / "nope"))
    with pytest.raises(FileNotFoundError):
        watcher.start()
