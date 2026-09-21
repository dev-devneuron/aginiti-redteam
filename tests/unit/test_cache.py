"""Tests for aginiti/providers/cache.py's shared cache-directory resolution."""
from __future__ import annotations

from pathlib import Path

from aginiti.providers.cache import cache_dir


class TestCacheDir:
    def test_creates_and_returns_the_namespaced_directory(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGINITI_CACHE_DIR", str(tmp_path))

        result = cache_dir("ikea_anchors")

        assert result == tmp_path / "ikea_anchors"
        assert result.is_dir()

    def test_different_namespaces_do_not_collide(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGINITI_CACHE_DIR", str(tmp_path))

        ikea = cache_dir("ikea_anchors")
        mia = cache_dir("ia_calibration")

        assert ikea != mia
        assert ikea.parent == mia.parent

    def test_falls_back_to_platformdirs_when_no_override_set(self, monkeypatch):
        monkeypatch.delenv("AGINITI_CACHE_DIR", raising=False)

        result = cache_dir("ikea_anchors")

        # Not asserting an exact OS-specific path -- just that it resolved
        # somewhere real, under the app's own namespace, not inside the
        # installed package's own directory (the bug this module fixes).
        assert result.is_dir()
        assert "aginiti-redteam" in str(result)
        assert "site-packages" not in str(result)

    def test_repeated_calls_are_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGINITI_CACHE_DIR", str(tmp_path))

        first = cache_dir("ikea_anchors")
        second = cache_dir("ikea_anchors")

        assert first == second
        assert first.is_dir()
