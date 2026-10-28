import json
import threading

import pytest

from core import logger


@pytest.fixture
def log_file(tmp_path):
    path = str(tmp_path / "test.log")
    logger.set_log_path(path)
    yield path
    logger.set_log_path(None)


def _lines(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_writes_one_valid_json_line_with_core_fields(log_file):
    logger.log("kill_process", incident_trace_id="abc", signals=["DECOY"], pid=42)
    (rec,) = _lines(log_file)
    assert rec["action"] == "kill_process" and rec["incident_trace_id"] == "abc"
    assert rec["signals"] == ["DECOY"] and rec["pid"] == 42 and rec["ts"] > 0


def test_extra_fields_cannot_override_core_fields(log_file):
    logger.log("act", pid=1, extra_info="hello")
    logger.log("act2", pid=2, **{"pid_extra": 5})
    first = _lines(log_file)[0]
    assert first["extra_info"] == "hello" and first["pid"] == 1
    # an attempt to smuggle in a second 'ts' must not replace the real one
    rec = logger.log("act3", ts="fake")
    assert rec["ts"] != "fake"


def test_trace_ids_are_short_and_unique():
    ids = {logger.new_trace_id() for _ in range(200)}
    assert len(ids) == 200 and all(len(i) == 12 for i in ids)


def test_concurrent_logging_never_mixes_lines(log_file):
    def work():
        for n in range(20):
            logger.log("tick", pid=n)
    threads = [threading.Thread(target=work) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(_lines(log_file)) == 100   # every line is intact valid JSON
