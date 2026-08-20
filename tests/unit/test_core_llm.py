"""Tests the key-rotation and Groq->Gemini fallback logic in
aginiti.core.llm, with litellm.completion mocked -- no live API calls.

Replaces tests/test_llm_client.py (retired 2026-08-20 alongside
aginiti/llm_client.py itself, as part of the LiteLLM-unification pass --
see aginiti/core/llm.py's own module docstring). Same behaviors under
test, same no-live-calls discipline; only the mocking target changed,
since aginiti.core.llm calls litellm.completion() directly instead of
constructing per-key groq.Groq() client objects.

tests/test_gemini_client.py has NO replacement here -- it tested the
retired aginiti/gemini_client.py's hand-rolled message/tool-schema
translation layer (_to_contents/_ToolCallShim/_MessageShim/
_to_gemini_tools), which has no equivalent in aginiti.core.llm at all:
LiteLLM already returns an OpenAI-compatible response for every provider
it routes to, Gemini included, so that translation code was deleted
outright rather than ported. Its correctness is LiteLLM's own test
suite's responsibility now, not this project's.
"""
import litellm
import pytest

import aginiti.core.llm as core_llm


def _rate_limit_error() -> litellm.RateLimitError:
    return litellm.RateLimitError("rate limited", llm_provider="groq", model="llama-3.3-70b-versatile")


def _fake_response(content="ok", tool_calls=None):
    message = type("Msg", (), {"content": content, "tool_calls": tool_calls})()
    choice = type("Choice", (), {"message": message})()
    return type("Resp", (), {"choices": [choice]})()


@pytest.fixture(autouse=True)
def reset_module_state(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    monkeypatch.delenv("GROQ_API_KEY_2", raising=False)
    monkeypatch.delenv("GROQ_API_KEY_3", raising=False)
    core_llm._current_idx = 0
    core_llm._last_fallback_reason = None
    yield
    core_llm._current_idx = 0
    core_llm._last_fallback_reason = None


def test_rotation_falls_through_to_next_key_on_rate_limit(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    monkeypatch.setenv("GROQ_API_KEY_2", "k1")
    calls = []

    def fake_completion(model, messages, api_key, **kwargs):
        calls.append(api_key)
        if api_key == "k0":
            raise _rate_limit_error()
        return _fake_response("ok-from-key1")

    monkeypatch.setattr(litellm, "completion", fake_completion)
    result = core_llm._call_with_rotation("groq/llama-3.3-70b-versatile", [{"role": "user", "content": "hi"}])

    assert result.choices[0].message.content == "ok-from-key1"
    assert calls == ["k0", "k1"]


def test_rotation_sticks_with_working_key_after_first_success(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    monkeypatch.setenv("GROQ_API_KEY_2", "k1")
    calls = []

    def fake_completion(model, messages, api_key, **kwargs):
        calls.append(api_key)
        if api_key == "k0":
            raise _rate_limit_error()
        return _fake_response("ok")

    monkeypatch.setattr(litellm, "completion", fake_completion)
    core_llm._call_with_rotation("groq/llama-3.3-70b-versatile", [{"role": "user", "content": "hi"}])
    calls.clear()

    # second call should go straight to k1, not retry k0 first
    core_llm._call_with_rotation("groq/llama-3.3-70b-versatile", [{"role": "user", "content": "hi"}])
    assert calls == ["k1"]


def test_rotation_raises_when_every_key_is_rate_limited(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    monkeypatch.setenv("GROQ_API_KEY_2", "k1")

    def fake_completion(model, messages, api_key, **kwargs):
        raise _rate_limit_error()

    monkeypatch.setattr(litellm, "completion", fake_completion)
    with pytest.raises(litellm.RateLimitError):
        core_llm._call_with_rotation("groq/llama-3.3-70b-versatile", [{"role": "user", "content": "hi"}])


# ---------------------------------------------------------------------------
# 2026-08-20 fix (integration Slice F, plans/PLAN.md): rotation broadened
# from litellm.RateLimitError alone to also cover AuthenticationError/
# BadRequestError -- live-verified during a real smoke test that an
# expired key raises BadRequestError, not RateLimitError, and the OLD
# rotation logic retried that same dead key forever at the sticky
# _current_idx instead of skipping to the next one in the pool.
# ---------------------------------------------------------------------------

def _bad_request_error() -> litellm.BadRequestError:
    return litellm.BadRequestError(
        'GroqException - {"error":{"message":"Invalid API Key","code":"expired_api_key"}}',
        llm_provider="groq", model="openai/gpt-oss-20b",
    )


def _authentication_error() -> litellm.AuthenticationError:
    return litellm.AuthenticationError("invalid api key", llm_provider="groq", model="openai/gpt-oss-20b")


def test_rotation_falls_through_to_next_key_on_bad_request_error(monkeypatch):
    # The exact live-observed bug: an expired key raises BadRequestError,
    # not RateLimitError -- must rotate past it, not retry it forever.
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    monkeypatch.setenv("GROQ_API_KEY_2", "k1")
    calls = []

    def fake_completion(model, messages, api_key, **kwargs):
        calls.append(api_key)
        if api_key == "k0":
            raise _bad_request_error()
        return _fake_response("ok-from-key1")

    monkeypatch.setattr(litellm, "completion", fake_completion)
    result = core_llm._call_with_rotation("groq/openai/gpt-oss-20b", [{"role": "user", "content": "hi"}])

    assert result.choices[0].message.content == "ok-from-key1"
    assert calls == ["k0", "k1"]


def test_rotation_falls_through_to_next_key_on_authentication_error(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    monkeypatch.setenv("GROQ_API_KEY_2", "k1")
    calls = []

    def fake_completion(model, messages, api_key, **kwargs):
        calls.append(api_key)
        if api_key == "k0":
            raise _authentication_error()
        return _fake_response("ok-from-key1")

    monkeypatch.setattr(litellm, "completion", fake_completion)
    result = core_llm._call_with_rotation("groq/openai/gpt-oss-20b", [{"role": "user", "content": "hi"}])

    assert result.choices[0].message.content == "ok-from-key1"
    assert calls == ["k0", "k1"]


def test_rotation_raises_when_every_key_is_a_bad_request(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    monkeypatch.setenv("GROQ_API_KEY_2", "k1")

    def fake_completion(model, messages, api_key, **kwargs):
        raise _bad_request_error()

    monkeypatch.setattr(litellm, "completion", fake_completion)
    with pytest.raises(litellm.BadRequestError):
        core_llm._call_with_rotation("groq/openai/gpt-oss-20b", [{"role": "user", "content": "hi"}])


def test_chat_falls_back_to_gemini_when_groq_pool_exhausted_by_bad_request_error(monkeypatch):
    # The outer chat()/chat_json()/chat_tools() fallback-to-Gemini path
    # must also trigger on the broadened exception set, not just
    # RateLimitError -- otherwise a pool exhausted by expired keys (as
    # opposed to rate limits) would crash instead of falling back.
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
    monkeypatch.setenv("GROQ_API_KEY", "k0")

    def fake_completion(model, messages, **kwargs):
        if model.startswith("groq/"):
            raise _bad_request_error()
        assert model.startswith("gemini/")
        return _fake_response("gemini-said-hi")

    monkeypatch.setattr(litellm, "completion", fake_completion)
    result = core_llm.chat([{"role": "user", "content": "hi"}])

    assert result == "gemini-said-hi"
    assert core_llm.last_fallback_reason() == "chat: groq pool exhausted, used gemini"


def test_groq_model_default_is_not_the_dead_llama_string():
    # 2026-08-20: llama-3.3-70b-versatile no longer exists on Groq at all
    # (confirmed live, 404), and the previously-suggested replacement
    # (llama-3.1-8b-instant) is also gone (confirmed live). Locks in the
    # new default so a future edit can't silently regress back to either
    # dead string.
    assert core_llm._GROQ_MODEL == "openai/gpt-oss-20b"


def test_load_groq_keys_reads_numbered_env_vars(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    monkeypatch.setenv("GROQ_API_KEY_2", "k1")
    monkeypatch.setenv("GROQ_API_KEY_3", "k2")
    monkeypatch.delenv("GROQ_API_KEY_4", raising=False)
    assert core_llm._load_groq_keys() == ["k0", "k1", "k2"]


# ---------------------------------------------------------------------------
# Automatic Groq -> Gemini fallback -- same behavior/tests as the retired
# test_llm_client.py, mocking litellm.completion's model= dispatch instead
# of a separate gemini_client module (there's only one call function now).
# ---------------------------------------------------------------------------

def test_chat_falls_back_to_gemini_when_groq_pool_exhausted(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")

    def fake_completion(model, messages, **kwargs):
        if model.startswith("groq/"):
            raise _rate_limit_error()
        assert model.startswith("gemini/")
        return _fake_response("gemini-said-hi")

    monkeypatch.setattr(litellm, "completion", fake_completion)
    result = core_llm.chat([{"role": "user", "content": "hi"}])

    assert result == "gemini-said-hi"
    assert core_llm.last_fallback_reason() == "chat: groq pool exhausted, used gemini"


def test_chat_json_falls_back_to_gemini_when_groq_pool_exhausted(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")

    def fake_completion(model, messages, **kwargs):
        if model.startswith("groq/"):
            raise _rate_limit_error()
        return _fake_response('{"ok": true}')

    monkeypatch.setattr(litellm, "completion", fake_completion)
    result = core_llm.chat_json([{"role": "user", "content": "hi"}])

    assert result == {"ok": True}
    assert core_llm.last_fallback_reason() == "chat_json: groq pool exhausted, used gemini"


def test_chat_tools_falls_back_to_gemini_when_groq_pool_exhausted(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
    sentinel_message = type("Msg", (), {"content": None, "tool_calls": ["fake_call"]})()

    def fake_completion(model, messages, **kwargs):
        if model.startswith("groq/"):
            raise _rate_limit_error()
        choice = type("Choice", (), {"message": sentinel_message})()
        return type("Resp", (), {"choices": [choice]})()

    monkeypatch.setattr(litellm, "completion", fake_completion)
    result = core_llm.chat_tools([{"role": "user", "content": "hi"}], tools=[])

    assert result is sentinel_message
    assert core_llm.last_fallback_reason() == "chat_tools: groq pool exhausted, used gemini"


def test_no_fallback_reason_recorded_when_groq_succeeds_directly(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
    monkeypatch.setattr(litellm, "completion", lambda model, messages, **kw: _fake_response("hello"))

    core_llm.chat([{"role": "user", "content": "hi"}])
    assert core_llm.last_fallback_reason() is None


def test_rate_limit_still_raises_when_no_gemini_key_configured(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(litellm, "completion", lambda model, messages, **kw: (_ for _ in ()).throw(_rate_limit_error()))

    with pytest.raises(litellm.RateLimitError):
        core_llm.chat([{"role": "user", "content": "hi"}])
    # No confusing secondary failure -- the real, original error surfaces.
    assert core_llm.last_fallback_reason() is None


def test_provider_is_never_mutated_by_a_fallback(monkeypatch):
    # A later, separate call must still try Groq first -- the fallback is
    # per-call, not a permanent provider switch (a key may recover, or
    # succeed under a different call shape's token budget).
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
    assert core_llm._PROVIDER == "groq"

    def fake_completion(model, messages, **kwargs):
        if model.startswith("groq/"):
            raise _rate_limit_error()
        return _fake_response("ok")

    monkeypatch.setattr(litellm, "completion", fake_completion)
    core_llm.chat([{"role": "user", "content": "hi"}])

    assert core_llm._PROVIDER == "groq"  # unchanged
