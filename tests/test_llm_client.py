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
