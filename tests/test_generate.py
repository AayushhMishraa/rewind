import hashlib
import json
import os

import pytest

import config
from database import db_manager
from detection.entropy_checker import calculate_entropy
from generate_samples import SandboxError, generate


def _paths(tmp_path):
    return dict(protected_dir=str(tmp_path / "protected"),
                safety_dir=str(tmp_path / "safety"),
                hashes_path=str(tmp_path / "data" / "hashes.json"),
                db_path=str(tmp_path / "t.db"),
                log_path=str(tmp_path / "t.log"))


def test_creates_100_big_files_and_the_sandbox_marker(tmp_path):
    p = _paths(tmp_path)
    generate(**p)
    docs = [f for f in os.listdir(p["protected_dir"]) if f.startswith("document_")]
    assert len(docs) == 100
    assert all(os.path.getsize(os.path.join(p["protected_dir"], f)) >= 8192 for f in docs)
    assert os.path.isfile(os.path.join(p["protected_dir"], config.SENTINEL_NAME))


def test_hash_file_matches_files_and_is_reproducible(tmp_path):
    p = _paths(tmp_path)
    first = generate(**p)
    with open(p["hashes_path"]) as f:
        saved = json.load(f)
    assert saved == first
    for name, expected in saved.items():
        with open(os.path.join(p["protected_dir"], name), "rb") as f:
            assert hashlib.sha256(f.read()).hexdigest() == expected
    assert generate(**p) == first   # same seed -> identical files


def test_refuses_to_wipe_a_folder_without_the_marker(tmp_path):
    p = _paths(tmp_path)
    os.makedirs(p["protected_dir"])
    precious = os.path.join(p["protected_dir"], "precious.txt")
    with open(precious, "w") as f:
        f.write("do not delete")
    with pytest.raises(SandboxError):
        generate(**p)
    assert os.path.exists(precious)


def test_wipes_old_content_when_marker_is_present(tmp_path):
    p = _paths(tmp_path)
    generate(**p)
    junk = os.path.join(p["protected_dir"], "junk.locked")
    with open(junk, "w") as f:
        f.write("leftover")
    generate(**p)
    assert not os.path.exists(junk)


def test_database_reset_unless_keep_db(tmp_path):
    p = _paths(tmp_path)
    db_manager.init_db(p["db_path"])
    generate(keep_db=True, **p)
    assert os.path.exists(p["db_path"])
    generate(keep_db=False, **p)
    assert not os.path.exists(p["db_path"])


def test_generated_documents_look_like_plain_text(tmp_path):
    p = _paths(tmp_path)
    generate(**p)
    for i in (0, 37, 99):
        path = os.path.join(p["protected_dir"], "document_%03d.txt" % i)
        assert calculate_entropy(path) < 6.5
