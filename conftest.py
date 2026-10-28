"""Makes the project root importable from the tests (so 'import config' works)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
"""Test setup: makes the project importable and keeps test logs out of the real rewind.log."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(autouse=True)
def _isolate_log_file(tmp_path_factory):
    from core import logger
    logger.set_log_path(str(tmp_path_factory.mktemp("logs") / "rewind-test.log"))
    yield
    logger.set_log_path(None)
