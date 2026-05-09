"""Tests for beigebox.security.safe_path."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from beigebox.security.safe_path import SafePath, UnsafePathError, resolve_under


def test_safepath_accepts_relative_under_base(tmp_path: Path):
    sp = SafePath("subdir/file.txt", base=tmp_path)
    assert sp.path == (tmp_path / "subdir" / "file.txt").resolve()
    assert sp.base == tmp_path.resolve()


def test_safepath_accepts_path_that_does_not_exist(tmp_path: Path):
    """Write paths must validate — file is created later."""
    sp = SafePath("does/not/exist/yet.txt", base=tmp_path)
    assert not sp.path.exists()


def test_safepath_rejects_dotdot_traversal(tmp_path: Path):
    base = tmp_path / "box"
    base.mkdir()
    with pytest.raises(UnsafePathError, match="outside base"):
        SafePath("../escape.txt", base=base)


def test_safepath_rejects_absolute_outside_base(tmp_path: Path):
    base = tmp_path / "box"
    base.mkdir()
    with pytest.raises(UnsafePathError, match="outside base"):
        SafePath("/etc/passwd", base=base)


def test_safepath_accepts_absolute_inside_base(tmp_path: Path):
    base = tmp_path / "box"
    base.mkdir()
    target = base / "ok.txt"
    sp = SafePath(str(target), base=base)
    assert sp.path == target.resolve()


def test_safepath_rejects_symlink_escape(tmp_path: Path):
    base = tmp_path / "box"
    base.mkdir()
    target = tmp_path / "outside_secret.txt"
    target.write_text("secret")
    link = base / "link"
    link.symlink_to(target)

    with pytest.raises(UnsafePathError, match="outside base"):
        SafePath("link", base=base)


def test_safepath_rejects_empty_string(tmp_path: Path):
    with pytest.raises(UnsafePathError, match="non-empty"):
        SafePath("", base=tmp_path)


def test_safepath_rejects_non_string(tmp_path: Path):
    with pytest.raises(UnsafePathError, match="must be str or Path"):
        SafePath(123, base=tmp_path)  # type: ignore[arg-type]


def test_safepath_works_as_pathlike(tmp_path: Path):
    """SafePath should be usable as os.PathLike (for open(), Path(), etc)."""
    sp = SafePath("hello.txt", base=tmp_path)
    assert os.fspath(sp).endswith("hello.txt")
    # Round-trips through Path()
    p2 = Path(sp)
    assert p2 == sp.path


def test_resolve_under_returns_path(tmp_path: Path):
    p = resolve_under("a/b.txt", base=tmp_path)
    assert isinstance(p, Path)
    assert p == (tmp_path / "a" / "b.txt").resolve()


def test_resolve_under_raises_on_escape(tmp_path: Path):
    with pytest.raises(UnsafePathError):
        resolve_under("../sneaky", base=tmp_path / "box")
