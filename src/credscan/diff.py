"""
Resolve the set of changed files for incremental (diff) scanning.

Per-commit scanning should look only at what changed, not re-walk the whole
repository. This returns absolute paths of files that are added/copied/
modified/renamed, either staged for commit or relative to a git ref.
"""

import logging
import os
import subprocess
from typing import List, Optional

logger = logging.getLogger(__name__)


def _repo_root(cwd: Optional[str] = None) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            cwd=cwd if cwd and os.path.isdir(cwd) else None,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def changed_files(
    ref: Optional[str] = None, scan_path: Optional[str] = None
) -> List[str]:
    """Return absolute paths of changed files.

    If ref is None, returns staged files (git diff --cached). Otherwise returns
    files changed relative to ref (git diff <ref>). Added/copied/modified/
    renamed only; deletions are excluded since there is nothing to scan. The
    git repository is resolved from scan_path so diff mode works when scanning
    a repository other than the current directory.
    """
    # Resolve the repo from the scan path (a directory, or a file's directory).
    cwd = None
    if scan_path:
        cwd = scan_path if os.path.isdir(scan_path) else os.path.dirname(scan_path)
    root = _repo_root(cwd)
    if not root:
        logger.warning("Not in a git repository; diff mode found no files")
        return []

    # Use -z (NUL-separated) so paths with spaces or non-ASCII characters are
    # emitted verbatim rather than git's octal-quoted form. Without this, a file
    # like "文档.md" would be skipped silently -- a dangerous miss for a scanner.
    if ref:
        cmd = ["git", "diff", "--name-only", "-z", "--diff-filter=ACMR", ref]
    else:
        cmd = ["git", "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"]

    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=root)
    except subprocess.CalledProcessError as e:
        logger.error(f"git diff failed: {e}")
        return []

    files = []
    for rel in out.stdout.split("\0"):
        if not rel:
            continue
        abs_path = os.path.join(root, rel)
        if os.path.isfile(abs_path):
            files.append(abs_path)
    return files
