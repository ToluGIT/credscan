"""
Robust resolution of the bundled `config/` directory.

The config files (comprehensive_patterns.json, context_patterns.json,
known_test_credentials.json, compliance_map.json, ...) live in a top-level
`config/` directory. Locating them via a fixed `../../../config` relative path
only works for a source/editable checkout; a packaged or containerized install
puts the code elsewhere. This resolver tries, in order:

  1. $CREDSCAN_CONFIG_DIR (explicit override; the Docker image sets this),
  2. the source-tree location relative to this file,
  3. the current working directory's `config/`.

It returns the first directory that exists, or the source-tree path as a last
resort so callers still get a usable (if absent) path to probe.
"""
import os

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# src/credscan/ -> repo root is two levels up; config/ sits beside src/.
_SOURCE_TREE_CONFIG = os.path.normpath(os.path.join(_THIS_DIR, "..", "..", "config"))


def get_config_dir() -> str:
    """Return the best available config directory path."""
    env = os.environ.get("CREDSCAN_CONFIG_DIR")
    candidates = [env] if env else []
    candidates.append(_SOURCE_TREE_CONFIG)
    candidates.append(os.path.join(os.getcwd(), "config"))
    for path in candidates:
        if path and os.path.isdir(path):
            return path
    return _SOURCE_TREE_CONFIG


def config_file(name: str) -> str:
    """Return the full path to a named file in the config directory."""
    return os.path.join(get_config_dir(), name)
