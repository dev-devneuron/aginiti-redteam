"""Tests the key-rotation logic in isolation, with fake clients -- no live
API calls."""
import httpx
import pytest
from groq import RateLimitError

import aginiti.llm_client as llm_client


def _rate_limit_error() -> RateLimitError:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    response = httpx.Response(429, request=request, json={"error": {"message": "rate limited"}})
    return RateLimitError("rate limited", response=response, body=None)


class _FakeCompletions:
    def __init__(self, behavior):
        self._behavior = behavior  # callable() -> result or raises

    def create(self, **kwargs):
        return self._behavior()


class _FakeChat:
    def __init__(self, behavior):
        self.completions = _FakeCompletions(behavior)


class _FakeClient:
    def __init__(self, behavior):
        self.chat = _FakeChat(behavior)


@pytest.fixture(autouse=True)
def reset_rotation_state():
    llm_client._clients = None
    llm_client._current_idx = 0
    yield
    llm_client._clients = None
    llm_client._current_idx = 0


def test_rotation_falls_through_to_next_key_on_rate_limit():
    calls = []

    def key0_behavior():
        calls.append("key0")
        raise _rate_limit_error()

    def key1_behavior():
        calls.append("key1")
        return "ok-from-key1"

    llm_client._clients = [_FakeClient(key0_behavior), _FakeClient(key1_behavior)]
    result = llm_client._call_with_rotation(lambda c: c.chat.completions.create())

    assert result == "ok-from-key1"
    assert calls == ["key0", "key1"]


def test_rotation_sticks_with_working_key_after_first_success():
    calls = []

    def key0_behavior():
        calls.append("key0")
        raise _rate_limit_error()

    def key1_behavior():
        calls.append("key1")
        return "ok"

    llm_client._clients = [_FakeClient(key0_behavior), _FakeClient(key1_behavior)]
    llm_client._call_with_rotation(lambda c: c.chat.completions.create())
    calls.clear()

    # second call should go straight to key1, not retry key0 first
    llm_client._call_with_rotation(lambda c: c.chat.completions.create())
    assert calls == ["key1"]


def test_rotation_raises_when_every_key_is_rate_limited():
    def always_limited():
        raise _rate_limit_error()

    llm_client._clients = [_FakeClient(always_limited), _FakeClient(always_limited)]
    with pytest.raises(RateLimitError):
        llm_client._call_with_rotation(lambda c: c.chat.completions.create())


def test_load_keys_reads_numbered_env_vars(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    monkeypatch.setenv("GROQ_API_KEY_2", "k1")
    monkeypatch.setenv("GROQ_API_KEY_3", "k2")
    monkeypatch.delenv("GROQ_API_KEY_4", raising=False)
    assert llm_client._load_keys() == ["k0", "k1", "k2"]


# ---------------------------------------------------------------------------
# Automatic Groq -> Gemini fallback (2026-08-09): every manual "swap the key,
# restart, retry" cycle that shows up repeatedly across this project's live-
# benchmark history is exactly what this closes -- when the WHOLE Groq pool
# is exhausted, chat/chat_json/chat_tools now fall back to gemini_client
# automatically, per call, without mutating _PROVIDER (a later call still
# tries Groq first). No live API calls -- gemini_client is mocked.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_fallback_state():
    llm_client._last_fallback_reason = None
    yield
    llm_client._last_fallback_reason = None


def _always_rate_limited_clients(n=2):
    def always_limited():
        raise _rate_limit_error()
    return [_FakeClient(always_limited) for _ in range(n)]


def test_chat_falls_back_to_gemini_when_groq_pool_exhausted(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
    llm_client._clients = _always_rate_limited_clients()
    import aginiti.gemini_client as gemini_client
    monkeypatch.setattr(gemini_client, "chat", lambda messages, temperature, max_tokens, seed: "gemini-said-hi")

    result = llm_client.chat([{"role": "user", "content": "hi"}])

    assert result == "gemini-said-hi"
    assert llm_client.last_fallback_reason() == "chat: groq pool exhausted, used gemini"


def test_chat_json_falls_back_to_gemini_when_groq_pool_exhausted(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
    llm_client._clients = _always_rate_limited_clients()
    import aginiti.gemini_client as gemini_client
    monkeypatch.setattr(gemini_client, "chat_json",
                         lambda messages, temperature, max_tokens, seed: {"ok": True})

    result = llm_client.chat_json([{"role": "user", "content": "hi"}])

    assert result == {"ok": True}
    assert llm_client.last_fallback_reason() == "chat_json: groq pool exhausted, used gemini"


def test_chat_tools_falls_back_to_gemini_when_groq_pool_exhausted(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
    llm_client._clients = _always_rate_limited_clients()
    import aginiti.gemini_client as gemini_client
    sentinel = object()
    monkeypatch.setattr(gemini_client, "chat_tools",
                         lambda messages, tools, temperature, max_tokens, seed: sentinel)

    result = llm_client.chat_tools([{"role": "user", "content": "hi"}], tools=[])

    assert result is sentinel
    assert llm_client.last_fallback_reason() == "chat_tools: groq pool exhausted, used gemini"


def test_no_fallback_reason_recorded_when_groq_succeeds_directly(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")

    class _FakeMsg:
        content = "hello"

    def ok():
        class _Resp:
            choices = [type("C", (), {"message": _FakeMsg()})]
        return _Resp()

    llm_client._clients = [_FakeClient(ok)]
    llm_client.chat([{"role": "user", "content": "hi"}])
    assert llm_client.last_fallback_reason() is None


def test_rate_limit_still_raises_when_no_gemini_key_configured(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    llm_client._clients = _always_rate_limited_clients()

    with pytest.raises(RateLimitError):
        llm_client.chat([{"role": "user", "content": "hi"}])
    # No confusing secondary failure -- the real, original error surfaces.
    assert llm_client.last_fallback_reason() is None


def test_provider_is_never_mutated_by_a_fallback(monkeypatch):
    # A later, separate call must still try Groq first -- the fallback is
    # per-call, not a permanent provider switch (a key may recover, or
    # succeed under a different call shape's token budget).
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
    assert llm_client._PROVIDER == "groq"
    llm_client._clients = _always_rate_limited_clients()
    import aginiti.gemini_client as gemini_client
    monkeypatch.setattr(gemini_client, "chat", lambda messages, temperature, max_tokens, seed: "ok")

    llm_client.chat([{"role": "user", "content": "hi"}])

    assert llm_client._PROVIDER == "groq"  # unchanged
