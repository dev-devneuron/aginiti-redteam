"""
Where the demo target agent persists its ChromaDB collection.

Resolved via ``platformdirs`` (a real per-user data directory) rather than a
path relative to this module's own location -- the original
``benchmarks/dev_fixtures`` fixture this package is adapted from used
``Path(__file__).parent / ".chroma"``, which for a ``pip install``-ed copy of
this library resolves inside ``site-packages/`` -- not reliably writable,
and wiped on every reinstall. Same reasoning as
``aginiti/providers/cache.py``'s cache-directory fix.

Override with ``AGINITI_DEMO_TARGET_DATA_DIR``.
"""
from __future__ import annotations

import os
from pathlib import Path

import platformdirs


def chroma_path() -> Path:
    """Return (and create) the directory the demo target's ChromaDB
    collection is persisted under."""
    override = os.environ.get("AGINITI_DEMO_TARGET_DATA_DIR")
    if override:
        base = Path(override)
    else:
        base = Path(platformdirs.user_data_dir("aginiti-redteam", appauthor=False))
    path = base / "demo_target" / "chroma"
    path.mkdir(parents=True, exist_ok=True)
    return path
