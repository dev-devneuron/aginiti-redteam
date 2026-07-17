import pytest
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
