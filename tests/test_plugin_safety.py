"""Tests for beigebox.security.plugin_safety."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

import pytest

from beigebox.security.plugin_safety import (
    UnsafePluginDirError,
    filter_by_allowlist,
    safe_plugin_dir,
)


# --- safe_plugin_dir ---------------------------------------------------------


def test_safe_plugin_dir_returns_none_when_missing(tmp_path: Path):
    missing = tmp_path / "nope"
    assert safe_plugin_dir(missing, project_root=tmp_path) is None


def test_safe_plugin_dir_returns_resolved_path_when_safe(tmp_path: Path):
    plugins = tmp_path / "plugins"
    plugins.mkdir(mode=0o750)
    result = safe_plugin_dir(plugins, project_root=tmp_path)
    assert result == plugins.resolve()


def test_safe_plugin_dir_rejects_world_writable(tmp_path: Path):
    plugins = tmp_path / "plugins"
    plugins.mkdir(mode=0o757)  # world-writable
    # mkdir's `mode` is masked by umask; force the bits we want
    os.chmod(plugins, 0o757)
    with pytest.raises(UnsafePluginDirError, match="world-writable"):
        safe_plugin_dir(plugins, project_root=tmp_path)


def test_safe_plugin_dir_rejects_path_outside_project_root(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(UnsafePluginDirError, match="escapes project root"):
        safe_plugin_dir(outside, project_root=project)


def test_safe_plugin_dir_rejects_traversal_in_string(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    traversal = project / ".." / "sibling"
    with pytest.raises(UnsafePluginDirError, match="escapes project root"):
        safe_plugin_dir(traversal, project_root=project)


def test_safe_plugin_dir_rejects_non_directory(tmp_path: Path):
    f = tmp_path / "not_a_dir.txt"
    f.write_text("hi")
    with pytest.raises(UnsafePluginDirError, match="not a directory"):
        safe_plugin_dir(f, project_root=tmp_path)


def test_safe_plugin_dir_permits_group_writable(tmp_path: Path):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    os.chmod(plugins, 0o770)  # group-writable, not world-writable
    assert safe_plugin_dir(plugins, project_root=tmp_path) == plugins.resolve()


# --- filter_by_allowlist -----------------------------------------------------


def _make_files(base: Path, names: list[str]) -> list[Path]:
    out = []
    for n in names:
        p = base / n
        p.write_text("# stub")
        out.append(p)
    return out


def test_filter_allowlist_none_yields_all_with_warning(tmp_path: Path, caplog):
    files = _make_files(tmp_path, ["a.py", "b.py", "c.py"])
    with caplog.at_level(logging.WARNING):
        result = list(filter_by_allowlist(files, None, context="test"))
    assert result == files
    assert any("no explicit allow-list" in r.message for r in caplog.records)


def test_filter_allowlist_empty_yields_nothing(tmp_path: Path):
    files = _make_files(tmp_path, ["a.py", "b.py"])
    result = list(filter_by_allowlist(files, [], context="test"))
    assert result == []


def test_filter_allowlist_yields_only_matching_stems(tmp_path: Path):
    files = _make_files(tmp_path, ["llama_cpp.py", "executorch.py", "evil.py"])
    result = list(filter_by_allowlist(files, ["llama_cpp", "executorch"], context="test"))
    assert sorted(p.name for p in result) == ["executorch.py", "llama_cpp.py"]


def test_filter_allowlist_does_not_match_substrings(tmp_path: Path):
    """`llama` should not match `llama_cpp.py` — exact stem only."""
    files = _make_files(tmp_path, ["llama_cpp.py"])
    result = list(filter_by_allowlist(files, ["llama"], context="test"))
    assert result == []
