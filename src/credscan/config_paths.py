"""
Robust resolution of the bundled `config/` directory.

The config files (comprehensive_patterns.json, context_patterns.json,
known_test_credentials.json, supported_extensions.json, wordlists/, ...) ship
INSIDE the package at `credscan/config/`, so they are present in every install
path: editable, wheel, sdist, and container. Resolution order:

  1. $CREDSCAN_CONFIG_DIR (explicit override),
  2. the in-package `credscan/config/` directory (the normal case),
  3. a legacy repo-root `config/` (older source checkouts),
  4. `<cwd>/config`.

Returns the first directory that exists, or the in-package path as a last
resort so callers still get a usable path to probe.
"""
import os

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# Shipped inside the package: credscan/config/
_PACKAGE_CONFIG = os.path.join(_THIS_DIR, "config")
# Legacy location for old source checkouts: <repo>/config (src/credscan -> ../../config)
_LEGACY_CONFIG = os.path.normpath(os.path.join(_THIS_DIR, "..", "..", "config"))


def get_config_dir() -> str:
    """Return the best available config directory path."""
    env = os.environ.get("CREDSCAN_CONFIG_DIR")
    candidates = [env] if env else []
    candidates.append(_PACKAGE_CONFIG)
    candidates.append(_LEGACY_CONFIG)
    candidates.append(os.path.join(os.getcwd(), "config"))
    for path in candidates:
        if path and os.path.isdir(path):
            return path
    return _PACKAGE_CONFIG


def config_file(name: str) -> str:
    """Return the full path to a named file in the config directory."""
    return os.path.join(get_config_dir(), name)
