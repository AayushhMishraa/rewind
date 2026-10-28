import hashlib
import os

from recovery.manifest import Manifest, build_manifest


def _write(path, data):
    os.makedirs(os.path.dirname(str(path)), exist_ok=True)
    with open(str(path), "wb") as f:
        f.write(data)


def test_build_manifest_contents_and_subfolders(tmp_path):
    _write(tmp_path / "a.txt", b"hello hello hello")
    _write(tmp_path / "sub" / "b.txt", b"second file")
    m = build_manifest(str(tmp_path))
    assert sorted(m) == ["a.txt", os.path.join("sub", "b.txt")]
    assert m["a.txt"]["sha256"] == hashlib.sha256(b"hello hello hello").hexdigest()
    assert m["a.txt"]["size"] == len(b"hello hello hello")
    assert 0.0 <= m["a.txt"]["entropy"] <= 8.0


def test_dotfiles_and_dotfolders_are_ignored(tmp_path):
    _write(tmp_path / ".REWIND_SANDBOX", b"marker")
    _write(tmp_path / ".hidden" / "x.txt", b"x")
    _write(tmp_path / "real.txt", b"real")
    assert sorted(build_manifest(str(tmp_path))) == ["real.txt"]


def test_symlinks_are_ignored(tmp_path):
    _write(tmp_path / "real.txt", b"real")
    os.symlink(str(tmp_path / "real.txt"), str(tmp_path / "link.txt"))
    assert sorted(build_manifest(str(tmp_path))) == ["real.txt"]


def test_manifest_lookups_accept_absolute_and_relative_paths(tmp_path):
    _write(tmp_path / "sub" / "b.txt", b"some text here " * 20)
    manifest = Manifest(root=str(tmp_path), data=build_manifest(str(tmp_path)))
    absolute = str(tmp_path / "sub" / "b.txt")
    relative = os.path.join("sub", "b.txt")
    assert manifest.contains(absolute) and manifest.contains(relative)
    assert not manifest.contains(str(tmp_path / "unknown.txt"))
    assert manifest.baseline_entropy(absolute) == manifest.get(relative)["entropy"]
    assert manifest.baseline_entropy(str(tmp_path / "unknown.txt")) is None
    assert len(manifest) == 1


def test_replace_and_rebuild(tmp_path):
    _write(tmp_path / "a.txt", b"aaa bbb ccc")
    manifest = Manifest(root=str(tmp_path))
    assert len(manifest) == 0
    manifest.rebuild()
    assert manifest.paths() == ["a.txt"]
    manifest.replace({})
    assert len(manifest) == 0
