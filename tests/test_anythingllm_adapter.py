"""Tests for AnythingLLMAdapter (aginiti/adapters/anythingllm_adapter.py).
No live server or network calls: requests.post is mocked throughout, same
discipline as test_dvaa_adapter.py / test_dvla_adapter.py.
"""
from unittest.mock import MagicMock, patch

import pytest

from aginiti.adapters.anythingllm_adapter import AnythingLLMAdapter
from aginiti.adapters.base import SendResult


def _fake_response(json_body, status_code=200, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_body
    resp.raise_for_status = MagicMock()
    return resp


def _adapter():
    return AnythingLLMAdapter(api_key="fake-key", workspace_slug="ws")


def test_direct_channel_posts_chat_and_extracts_text_and_sources():
    adapter = _adapter()
    fake = _fake_response({
        "textResponse": "hello from the target",
        "sources": [{"title": "doc1.txt", "id": "abc", "text": "chunk content" * 100}],
    })
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake) as mock_post:
        result = adapter.send("direct", "hi")

    url, kwargs = mock_post.call_args
    assert url[0] == "http://localhost:3001/api/v1/workspace/ws/chat"
    assert kwargs["json"] == {"message": "hi", "mode": "chat"}
    assert result.final_text == "hello from the target"
    assert result.is_synthetic is False
    assert result.tool_trace == [{"tool": "vector_search_source",
                                   "args": {"title": "doc1.txt", "docId": "abc",
                                            "text": ("chunk content" * 100)[:500]}}]


def test_direct_channel_with_no_sources_produces_empty_tool_trace():
    adapter = _adapter()
    fake = _fake_response({"textResponse": "no sources here"})
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake):
        result = adapter.send("direct", "hi")

    assert result.tool_trace == []


def test_unknown_channel_raises_value_error():
    adapter = _adapter()
    with pytest.raises(ValueError, match="only supports channel"):
        adapter.send("carrier-pigeon", "hi")


def test_plant_channel_uploads_document_and_returns_raw_response():
    adapter = _adapter()
    fake = _fake_response({"success": True, "error": None, "documents": [{"id": "doc-1"}]})
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake) as mock_post:
        result = adapter.send("plant", "some document content")

    url, kwargs = mock_post.call_args
    assert url[0] == "http://localhost:3001/api/v1/document/upload"
    assert kwargs["files"]["file"][1] == b"some document content"
    assert kwargs["data"] == {"addToWorkspaces": "ws"}
    assert "'success': True" in result.final_text
    assert isinstance(result, SendResult)


def test_rate_limit_500_is_retried_then_succeeds():
    adapter = _adapter()
    rate_limited = _fake_response({}, status_code=500, text="Error: rate limit reached, try again in 0.01s")
    ok = _fake_response({"textResponse": "finally worked", "sources": []})
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", side_effect=[rate_limited, ok]), \
         patch("aginiti.adapters.anythingllm_adapter.time.sleep") as mock_sleep:
        result = adapter.send("direct", "hi")

    mock_sleep.assert_called_once()
    assert result.final_text == "finally worked"


def test_rate_limit_500_exhausts_retries_and_returns_synthetic_result():
    """2026-08-12 hardening-pass fix: exhausting retries on a persistently
    rate-limited target must NOT crash the whole campaign (the pre-fix
    behavior this test used to lock in) -- it's classified as
    TargetUnavailable internally and surfaced as an explicit
    is_synthetic=True SendResult, which ObservationAdapter can never
    mistake for genuine target evidence in either direction."""
    adapter = _adapter()
    rate_limited = _fake_response({}, status_code=500, text="Error: rate limit reached, try again in 0.01s")
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=rate_limited), \
         patch("aginiti.adapters.anythingllm_adapter.time.sleep"):
        result = adapter.send("direct", "hi")

    assert result.is_synthetic is True
    assert "target unavailable" in result.final_text.lower()


def test_non_rate_limit_500_is_not_retried_and_returns_synthetic_result():
    adapter = _adapter()
    import requests
    server_error = MagicMock()
    server_error.status_code = 500
    server_error.text = "internal server error, some other unrelated failure"
    server_error.raise_for_status.side_effect = requests.exceptions.HTTPError("500")
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=server_error) as mock_post:
        result = adapter.send("direct", "hi")

    assert mock_post.call_count == 1  # no retry loop entered for a non-rate-limit failure
    assert result.is_synthetic is True


def test_connection_error_returns_synthetic_result_not_a_crash():
    """2026-08-12 hardening-pass fix: a genuinely down/unreachable target
    (connection refused) previously propagated requests.exceptions.
    ConnectionError all the way up through ObservationAdapter/
    run_campaign, uncaught -- now classified and non-retried (a hung
    target won't recover in the next few seconds)."""
    import requests

    adapter = _adapter()
    with patch("aginiti.adapters.anythingllm_adapter.requests.post",
               side_effect=requests.exceptions.ConnectionError("refused")) as mock_post:
        result = adapter.send("direct", "hi")

    assert mock_post.call_count == 1  # not retried
    assert result.is_synthetic is True
    assert "unavailable" in result.final_text.lower() or "unreachable" in result.final_text.lower()


def test_timeout_returns_synthetic_result_not_a_crash():
    import requests

    adapter = _adapter()
    with patch("aginiti.adapters.anythingllm_adapter.requests.post",
               side_effect=requests.exceptions.Timeout("timed out")):
        result = adapter.send("direct", "hi")

    assert result.is_synthetic is True


def test_malformed_json_body_returns_synthetic_result_not_a_crash():
    """2026-08-12 hardening-pass fix: resp.json() raising on a non-JSON
    body (e.g. an HTML error page from a proxy) previously propagated as a
    raw exception from deep inside a dict-shaped call site."""
    adapter = _adapter()
    bad = MagicMock()
    bad.status_code = 200
    bad.text = "<html>not json</html>"
    bad.raise_for_status = MagicMock()
    bad.json.side_effect = ValueError("Expecting value")
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=bad):
        result = adapter.send("direct", "hi")

    assert result.is_synthetic is True
    assert "malformed" in result.final_text.lower()


def test_plant_channel_also_classifies_target_failures():
    import requests

    adapter = _adapter()
    with patch("aginiti.adapters.anythingllm_adapter.requests.post",
               side_effect=requests.exceptions.ConnectionError("refused")):
        result = adapter.send("plant", "some document content")

    assert result.is_synthetic is True


def test_synthetic_failure_text_never_satisfies_ground_truth():
    """A registered canary must never accidentally appear inside the
    adapter's own synthesized failure text -- would be a false positive
    exactly as dangerous as the ones this project's is_synthetic
    convention already exists to prevent."""
    import requests

    adapter = _adapter()
    adapter.register_canary("MY-UNIQUE-CANARY-TOKEN")
    with patch("aginiti.adapters.anythingllm_adapter.requests.post",
               side_effect=requests.exceptions.ConnectionError("refused")):
        adapter.send("direct", "hi")

    assert adapter.ground_truth_mission_achieved() is False


def test_ground_truth_false_with_no_canaries_registered():
    adapter = _adapter()
    fake = _fake_response({"textResponse": "anything at all", "sources": []})
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake):
        adapter.send("direct", "hi")

    assert adapter.ground_truth_mission_achieved() is False


def test_ground_truth_true_only_after_registered_canary_appears_in_a_response():
    adapter = _adapter()
    fake = _fake_response({"textResponse": "here is CANARY-XYZ embedded", "sources": []})
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake):
        adapter.send("direct", "hi")

    assert adapter.ground_truth_mission_achieved() is False  # not registered yet
    adapter.register_canary("CANARY-XYZ")
    assert adapter.ground_truth_mission_achieved() is True  # now matches a recorded raw response


def test_plant_channel_response_never_counts_as_ground_truth_evidence():
    # Regression test for a live-caught false positive (2026-08-08,
    # automatic-mode pass): AnythingLLM's real /document/upload response
    # echoes the planted content back verbatim in a `pageContent` field,
    # so a canary just planted would otherwise trivially satisfy
    # ground_truth_mission_achieved() without any genuine later retrieval
    # or tool-call ever happening -- caught via a live end-to-end run
    # where a fresh canary showed True with zero corroborating evidence in
    # either the trigger response or the independent listener log.
    adapter = _adapter()
    canary = "PLANT-ECHO-CANARY"
    fake = _fake_response({
        "success": True, "error": None,
        "documents": [{"id": "doc-1", "pageContent": f"some content with {canary} inside it"}],
    })
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake):
        adapter.send("plant", f"some content with {canary} inside it")

    adapter.register_canary(canary)
    assert adapter.ground_truth_mission_achieved() is False  # the plant's own echo must not count


def test_chat_mode_constructor_param_overrides_default_chat_mode():
    adapter = AnythingLLMAdapter(api_key="fake-key", workspace_slug="ws", chat_mode="automatic")
    fake = _fake_response({"textResponse": "hi", "sources": []})
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake) as mock_post:
        adapter.send("direct", "hello")

    _, kwargs = mock_post.call_args
    assert kwargs["json"] == {"message": "hello", "mode": "automatic"}


def test_automatic_channel_always_sends_mode_automatic_regardless_of_chat_mode():
    adapter = AnythingLLMAdapter(api_key="fake-key", workspace_slug="ws", chat_mode="chat")
    fake = _fake_response({"textResponse": "hi", "sources": [], "thoughts": []})
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake) as mock_post:
        adapter.send("automatic", "hello")

    _, kwargs = mock_post.call_args
    assert kwargs["json"] == {"message": "hello", "mode": "automatic"}


def test_automatic_channel_folds_thoughts_into_final_text():
    adapter = _adapter()
    fake = _fake_response({
        "textResponse": "The answer is 4 hours.",
        "sources": [],
        "thoughts": [
            "@agent is executing `web-scraping` tool {\"url\": \"http://127.0.0.1:8901/verify?token=ABC\"}",
            "@agent: Scraping the content of http://127.0.0.1:8901/verify?token=ABC",
        ],
    })
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake):
        result = adapter.send("automatic", "what's the response time?")

    assert "The answer is 4 hours." in result.final_text
    assert "web-scraping" in result.final_text
    assert "token=ABC" in result.final_text


def test_automatic_channel_with_no_thoughts_leaves_final_text_as_just_the_response():
    adapter = _adapter()
    fake = _fake_response({"textResponse": "4", "sources": [], "thoughts": []})
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake):
        result = adapter.send("automatic", "what is 2+2?")

    assert result.final_text == "4"


def test_automatic_channel_parses_tool_call_from_thoughts_into_tool_trace():
    adapter = _adapter()
    fake = _fake_response({
        "textResponse": "done",
        "sources": [],
        "thoughts": ['@agent is executing `web-scraping` tool {\n  "url": "https://example.com"\n}'],
    })
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake):
        result = adapter.send("automatic", "hi")

    tool_names = [t["tool"] for t in result.tool_trace]
    assert "web-scraping" in tool_names


def test_ground_truth_checks_registered_exfil_listener_log(tmp_path):
    adapter = _adapter()
    fake = _fake_response({"textResponse": "no canary in the chat text at all", "sources": [], "thoughts": []})
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake):
        adapter.send("automatic", "hi")

    log_path = tmp_path / "listener_hits.log"
    log_path.write_text("2026-08-08T00:00:00 GET /verify?token=CANARY-IN-LOG-ONLY\n")

    adapter.register_canary("CANARY-IN-LOG-ONLY")
    assert adapter.ground_truth_mission_achieved() is False  # not registered yet

    adapter.register_exfil_listener_log(str(log_path))
    assert adapter.ground_truth_mission_achieved() is True  # found in the THIRD-PARTY log, not chat text


def test_ground_truth_listener_log_missing_file_returns_false_not_raise(tmp_path):
    adapter = _adapter()
    adapter.register_canary("SOME-CANARY")
    adapter.register_exfil_listener_log(str(tmp_path / "does-not-exist.log"))
    assert adapter.ground_truth_mission_achieved() is False


def test_upload_link_posts_to_upload_link_endpoint():
    adapter = _adapter()
    fake = _fake_response({"success": True})
    with patch("aginiti.adapters.anythingllm_adapter.requests.post", return_value=fake) as mock_post:
        adapter.upload_link("https://example.com/page")

    url, kwargs = mock_post.call_args
    assert url[0] == "http://localhost:3001/api/v1/document/upload-link"
    assert kwargs["json"] == {"link": "https://example.com/page", "addToWorkspaces": "ws"}
