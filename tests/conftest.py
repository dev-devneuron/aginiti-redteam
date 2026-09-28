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


@pytest.fixture(autouse=True)
def _isolate_deep_attack_operator_models(monkeypatch):
    """`aginiti scan` writes these straight into os.environ (so the
    deep-attack operator factories see them); resetting them per test keeps
    one scan test's auto-detected model from leaking into later tests."""
    for var in ("IKEA_OPERATOR_LLM_PROVIDER", "SECRET_OPERATOR_LLM_PROVIDER",
                "MIA_OPERATOR_LLM_PROVIDER", "SPE_OPERATOR_LLM_PROVIDER"):
        monkeypatch.delenv(var, raising=False)
