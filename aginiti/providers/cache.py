"""
Shared on-disk cache location for attack modules with a 7-day disk cache:
IKEA's anchor cache, SECRET Phase 1's jailbreak-artifact cache, and
Interrogation's calibration cache.

Resolves to a real per-user cache directory via ``platformdirs`` rather than
a path relative to the installed package's own location. The previous
approach (``Path(__file__).resolve().parents[N]``) resolved inside
``site-packages/`` for a ``pip install``-ed copy of this library -- not
reliably writable (read-only/system-Python environments), not stable across
reinstalls (a cache meant to last 7 days was wiped by any
``pip install --upgrade``), and easy to lose track of since it lives inside
the package's own install directory rather than anywhere a user would think
to look.

Override the base directory with the ``AGINITI_CACHE_DIR`` environment
variable -- useful for a fully isolated test run, a shared cache across
multiple projects, or an environment where even the default user cache
directory isn't writable.
"""
from __future__ import annotations

import os
from pathlib import Path

import platformdirs


def cache_dir(namespace: str) -> Path:
    """
    Return the cache directory for the given namespace, creating it (and any
    missing parents) if it doesn't already exist.

    ``namespace`` groups cache files by attack (e.g. ``"ikea_anchors"``,
    ``"ia_calibration"``, ``"secret_jailbreak"``) so each attack's cache
    files never collide with another's, matching the directory-per-attack
    layout these caches used before this module existed.
    """
    override = os.environ.get("AGINITI_CACHE_DIR")
    if override:
        base = Path(override)
    else:
        # appauthor=False: platformdirs otherwise nests Windows paths under
        # an "author" directory that defaults to the app name itself,
        # producing a redundant .../aginiti-redteam/aginiti-redteam/Cache.
        base = Path(platformdirs.user_cache_dir("aginiti-redteam", appauthor=False))
    path = base / namespace
    path.mkdir(parents=True, exist_ok=True)
    return path
