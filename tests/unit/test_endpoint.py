import pytest
import requests
import responses as resp_lib
from requests.exceptions import HTTPError

from aginiti.connectors.endpoint import AgentEndpoint


BASE = "http://localhost:8001"


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_chat_returns_response_text():
    resp_lib.add(resp_lib.POST, f"{BASE}/chat",
                 json={"response": "Emma Thompson's salary is $152,000."}, status=200)

    ep = AgentEndpoint(base_url=BASE)
    result = ep.chat("What is Emma Thompson's salary?")
    assert result == "Emma Thompson's salary is $152,000."


@resp_lib.activate
def test_chat_sends_correct_payload():
    def _callback(request):
        import json
        body = json.loads(request.body)
        assert body == {"message": "hello"}
        return (200, {}, '{"response": "hi"}')

    resp_lib.add_callback(resp_lib.POST, f"{BASE}/chat", callback=_callback,
                          content_type="application/json")

    ep = AgentEndpoint(base_url=BASE)
    ep.chat("hello")


@resp_lib.activate
def test_chat_custom_request_and_response_keys():
    resp_lib.add(resp_lib.POST, f"{BASE}/query",
                 json={"answer": "42"}, status=200)

    ep = AgentEndpoint(base_url=BASE, request_key="query", response_key="answer")
    result = ep.chat("the question", endpoint="/query")
    assert result == "42"


@resp_lib.activate
def test_base_url_trailing_slash_stripped():
    resp_lib.add(resp_lib.POST, f"{BASE}/chat",
                 json={"response": "ok"}, status=200)

    ep = AgentEndpoint(base_url=BASE + "/")
    assert ep.chat("x") == "ok"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_missing_response_key_raises_key_error():
    resp_lib.add(resp_lib.POST, f"{BASE}/chat",
                 json={"wrong_key": "data"}, status=200)

    ep = AgentEndpoint(base_url=BASE, max_retries=0)
    with pytest.raises(KeyError, match="response"):
        ep.chat("hello")


@resp_lib.activate
def test_http_500_raises_after_retries():
    # Register enough responses to cover retries
    for _ in range(4):
        resp_lib.add(resp_lib.POST, f"{BASE}/chat", status=500)

    ep = AgentEndpoint(base_url=BASE, max_retries=0, backoff_factor=0)
    with pytest.raises(HTTPError):
        ep.chat("hello")


@resp_lib.activate
def test_http_4xx_raises_immediately_no_retry():
    # Only one 400 registered — if retry happened it would raise ConnectionError
    resp_lib.add(resp_lib.POST, f"{BASE}/chat", status=400)

    ep = AgentEndpoint(base_url=BASE, max_retries=3, backoff_factor=0)
    with pytest.raises(HTTPError):
        ep.chat("hello")

    # Exactly one call was made (no retry on 4xx)
    assert len(resp_lib.calls) == 1


# ---------------------------------------------------------------------------
# 429 rate-limit handling (added 2026-08-08 — found live while preparing a
# real MIA run against hardened_agent, whose RateLimiter returns a bare 429
# with no Retry-After header; see AgentEndpoint's docstring)
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_429_retried_with_rate_limit_wait_not_dropped(monkeypatch):
    sleeps = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))

    resp_lib.add(resp_lib.POST, f"{BASE}/chat", status=429)
    resp_lib.add(resp_lib.POST, f"{BASE}/chat",
                 json={"response": "ok after retry"}, status=200)

    ep = AgentEndpoint(base_url=BASE, max_retries=1, rate_limit_wait_seconds=65.0)
    result = ep.chat("hello")

    assert result == "ok after retry"
    assert len(resp_lib.calls) == 2
    assert sleeps == [65.0]  # rate-limit wait used, not the normal backoff_factor schedule


@resp_lib.activate
def test_429_honors_retry_after_header(monkeypatch):
    sleeps = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))

    resp_lib.add(resp_lib.POST, f"{BASE}/chat", status=429, headers={"Retry-After": "12"})
    resp_lib.add(resp_lib.POST, f"{BASE}/chat", json={"response": "ok"}, status=200)

    ep = AgentEndpoint(base_url=BASE, max_retries=1, rate_limit_wait_seconds=65.0)
    ep.chat("hello")

    assert sleeps == [12.0]  # target's own Retry-After honored over the default


@resp_lib.activate
def test_429_exhausts_retries_then_raises():
    for _ in range(3):
        resp_lib.add(resp_lib.POST, f"{BASE}/chat", status=429)

    ep = AgentEndpoint(base_url=BASE, max_retries=2, rate_limit_wait_seconds=0.0)
    with pytest.raises(HTTPError) as exc_info:
        ep.chat("hello")

    assert exc_info.value.response.status_code == 429
    assert len(resp_lib.calls) == 3  # initial + 2 retries


@resp_lib.activate
def test_429_does_not_consume_normal_backoff_schedule():
    # A 429 followed by success shouldn't leave next_wait leaking into a
    # LATER, unrelated call on the same AgentEndpoint instance.
    resp_lib.add(resp_lib.POST, f"{BASE}/chat", status=429)
    resp_lib.add(resp_lib.POST, f"{BASE}/chat", json={"response": "first"}, status=200)
    resp_lib.add(resp_lib.POST, f"{BASE}/chat", status=500)
    resp_lib.add(resp_lib.POST, f"{BASE}/chat", json={"response": "second"}, status=200)

    ep = AgentEndpoint(base_url=BASE, max_retries=1, rate_limit_wait_seconds=0.0, backoff_factor=0)
    assert ep.chat("a") == "first"
    assert ep.chat("b") == "second"  # the later 500 retries on its own fresh schedule


def test_send_fn_429_retried_with_rate_limit_wait(monkeypatch):
    sleeps = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))
    attempts = []

    def _send_fn(session, url, message, timeout):
        attempts.append(1)
        if len(attempts) == 1:
            response = requests.Response()
            response.status_code = 429
            raise HTTPError(response=response)
        return "ok"

    ep = AgentEndpoint(base_url=BASE, send_fn=_send_fn, max_retries=1, rate_limit_wait_seconds=65.0)
    assert ep.chat("hello") == "ok"
    assert len(attempts) == 2
    assert sleeps == [65.0]


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

def test_context_manager_returns_self():
    ep = AgentEndpoint(base_url=BASE)
    with ep as inner:
        assert inner is ep


def test_close_does_not_raise():
    ep = AgentEndpoint(base_url=BASE)
    ep.close()
    ep.close()  # double-close should be safe


# ---------------------------------------------------------------------------
# headers / send_fn (added 2026-07-23 — generic auth + pluggable request/
# response shape, first real caller is the Onyx connector; see
# aginiti/attacks/dra/ikea.py's endpoint_kwargs and
# benchmarks/scaled_evals/agents/onyx_target/connector.py)
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_headers_sent_on_every_request():
    def _callback(request):
        assert request.headers.get("Authorization") == "Bearer secret-key"
        return (200, {}, '{"response": "ok"}')

    resp_lib.add_callback(resp_lib.POST, f"{BASE}/chat", callback=_callback,
                          content_type="application/json")

    ep = AgentEndpoint(base_url=BASE, headers={"Authorization": "Bearer secret-key"})
    assert ep.chat("hello") == "ok"


@resp_lib.activate
def test_headers_applied_to_check_reachable_too():
    def _callback(request):
        assert request.headers.get("Authorization") == "Bearer secret-key"
        return (200, {}, "{}")

    resp_lib.add_callback(resp_lib.GET, f"{BASE}/health", callback=_callback,
                          content_type="application/json")

    ep = AgentEndpoint(base_url=BASE, headers={"Authorization": "Bearer secret-key"})
    assert ep.check_reachable() is True


def test_send_fn_overrides_default_request_shape():
    calls = []

    def _send_fn(session, url, message, timeout):
        calls.append((url, message, timeout))
        return f"echo: {message}"

    ep = AgentEndpoint(base_url=BASE, send_fn=_send_fn)
    result = ep.chat("hello")

    assert result == "echo: hello"
    assert calls == [(f"{BASE}/chat", "hello", 30)]


def test_send_fn_4xx_http_error_not_retried():
    attempts = []

    def _send_fn(session, url, message, timeout):
        attempts.append(1)
        response = requests.Response()
        response.status_code = 400
        raise HTTPError(response=response)

    ep = AgentEndpoint(base_url=BASE, send_fn=_send_fn, max_retries=3, backoff_factor=0)
    with pytest.raises(HTTPError):
        ep.chat("hello")

    assert len(attempts) == 1  # no retry on 4xx, same contract as the default path


def test_send_fn_5xx_retried_then_raises():
    attempts = []

    def _send_fn(session, url, message, timeout):
        attempts.append(1)
        response = requests.Response()
        response.status_code = 500
        raise HTTPError(response=response)

    ep = AgentEndpoint(base_url=BASE, send_fn=_send_fn, max_retries=2, backoff_factor=0)
    with pytest.raises(HTTPError):
        ep.chat("hello")

    assert len(attempts) == 3  # initial + 2 retries, same contract as the default path
