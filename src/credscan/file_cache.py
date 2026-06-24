"""
Bounded, thread-safe file-content cache.

During a scan each file is read several times in quick succession (the parser,
the enhanced pattern pass, and the entropy analyzer each open it). This cache
collapses those into a single disk read per file while keeping memory bounded:
it is an LRU keyed by (path, mtime, size), so it never holds more than a fixed
number of files' contents at once and transparently re-reads if a file changes.
"""
import functools
import os
from typing import Optional

# Cap the number of cached file contents. Files are read ~3x in immediate
# succession per worker, so a modest cache captures the win without growing
# unbounded on a large repository.
_MAX_CACHED_FILES = 128


@functools.lru_cache(maxsize=_MAX_CACHED_FILES)
def _read_cached(path: str, _mtime: float, _size: int) -> str:
    # The mtime/size are part of the cache key (so edits invalidate) but are
    # not used in the body.
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def read_text(path: str) -> Optional[str]:
    """Read a file's text, using a bounded LRU cache. Returns None on error."""
    try:
        st = os.stat(path)
        return _read_cached(path, st.st_mtime, st.st_size)
    except Exception:
        return None


def clear() -> None:
    """Clear the cache (used by tests)."""
    _read_cached.cache_clear()
