"""Tests for incremental/diff scanning and the bounded file cache."""
import os
import subprocess

import pytest

from credscan import file_cache
from credscan.diff import changed_files


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


@pytest.fixture
def git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init"], str(repo))
    _git(["config", "user.email", "t@t.co"], str(repo))
    _git(["config", "user.name", "t"], str(repo))
    (repo / "clean.py").write_text("x = 1\n")
    _git(["add", "clean.py"], str(repo))
    _git(["commit", "-m", "init"], str(repo))
    return repo


class TestChangedFiles:
    def test_staged_files_only(self, git_repo):
        (git_repo / "leak.py").write_text('AWS_ACCESS_KEY_ID = "AKIAY2K7MNQ4RST6UVWX"\n')
        _git(["add", "leak.py"], str(git_repo))
        files = changed_files(scan_path=str(git_repo))
        assert len(files) == 1
        assert files[0].endswith("leak.py")

    def test_nothing_staged_returns_empty(self, git_repo):
        files = changed_files(scan_path=str(git_repo))
        assert files == []

    def test_diff_vs_ref(self, git_repo):
        # Create a second commit and diff against the first.
        (git_repo / "new.py").write_text("y = 2\n")
        _git(["add", "new.py"], str(git_repo))
        _git(["commit", "-m", "second"], str(git_repo))
        files = changed_files(ref="HEAD~1", scan_path=str(git_repo))
        assert any(f.endswith("new.py") for f in files)

    def test_outside_git_returns_empty(self, tmp_path):
        # A non-git directory yields no changed files rather than erroring.
        d = tmp_path / "plain"
        d.mkdir()
        assert changed_files(scan_path=str(d)) == []


class TestExplicitFilesScan:
    def test_engine_scans_only_explicit_files(self, git_repo):
        from credscan.core.engine import ScanEngine
        (git_repo / "a.py").write_text("a = 1\n")
        (git_repo / "b.py").write_text("b = 2\n")
        only = [str(git_repo / "a.py")]
        engine = ScanEngine({"scan_path": str(git_repo), "explicit_files": only})
        found = engine.find_files()
        assert found == only


class TestFileCache:
    def test_reads_and_caches(self, tmp_path):
        file_cache.clear()
        p = tmp_path / "f.txt"
        p.write_text("hello cache")
        assert file_cache.read_text(str(p)) == "hello cache"
        # Second read returns the same content (served from cache).
        assert file_cache.read_text(str(p)) == "hello cache"

    def test_missing_file_returns_none(self, tmp_path):
        assert file_cache.read_text(str(tmp_path / "nope.txt")) is None

    def test_edit_invalidates_cache(self, tmp_path):
        file_cache.clear()
        p = tmp_path / "f.txt"
        p.write_text("v1xxxxxxxx")
        assert file_cache.read_text(str(p)) == "v1xxxxxxxx"
        # Rewrite with different length so (mtime,size) key changes.
        p.write_text("v2-different-content")
        assert file_cache.read_text(str(p)) == "v2-different-content"
