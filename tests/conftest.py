"""Suite-wide test isolation."""
import pytest


@pytest.fixture(autouse=True)
def _isolate_any_provider_override(monkeypatch):
    """AGINITI_LLM_MODEL outranks every built-in provider (see
    aginiti/providers/llm.py), and aginiti.providers.llm loads the
    developer's own .env at import time -- so a local .env that sets it
    would silently reroute every provider-routing test. Tests that exercise
    the override set it explicitly."""
    monkeypatch.delenv("AGINITI_LLM_MODEL", raising=False)
    monkeypatch.delenv("AGINITI_LLM_API_KEY", raising=False)
