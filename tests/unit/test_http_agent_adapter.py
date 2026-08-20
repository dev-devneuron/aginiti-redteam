"""Tests for HTTPAgentAdapter (aginiti/adapters/http_agent_adapter.py,
Phase 2 Slice A -- plans/phase2-operator-wrapping.md).

No live server or network calls: AgentEndpoint itself is mocked (this
class is a thin wrapper around it, so mocking AgentEndpoint.chat directly
is the right boundary -- AgentEndpoint's own HTTP behavior is already
covered by its own test suite), same "mock at the real boundary" discipline
as every other adapter test in this project.
"""
from unittest.mock import MagicMock

import pytest

from aginiti.adapters.base import SendResult
from aginiti.adapters.http_agent_adapter import HTTPAgentAdapter
from aginiti.connectors.endpoint import AgentEndpoint


def _mock_endpoint() -> MagicMock:
    return MagicMock(spec=AgentEndpoint)


def test_direct_channel_delegates_to_endpoint_chat_and_wraps_result():
    endpoint = _mock_endpoint()
    endpoint.chat.return_value = "hello from the target"
    adapter = HTTPAgentAdapter(endpoint)

    result = adapter.send("direct", "hi")

    endpoint.chat.assert_called_once_with("hi")
    assert isinstance(result, SendResult)
    assert result.final_text == "hello from the target"
    assert result.tool_trace == []
    assert result.is_synthetic is False


def test_non_direct_channel_raises_value_error_without_calling_endpoint():
    endpoint = _mock_endpoint()
    adapter = HTTPAgentAdapter(endpoint)

    with pytest.raises(ValueError, match="only supports channel='direct'"):
        adapter.send("slack", "plant this")

    endpoint.chat.assert_not_called()


def test_endpoint_exception_becomes_synthetic_send_result_not_a_crash():
    endpoint = _mock_endpoint()
    endpoint.chat.side_effect = ConnectionError("connection refused")
    adapter = HTTPAgentAdapter(endpoint)

    result = adapter.send("direct", "hi")

    assert result.is_synthetic is True
    assert "ConnectionError" in result.final_text
    assert "connection refused" in result.final_text


def test_endpoint_generic_exception_also_becomes_synthetic_not_a_crash():
    # Deliberately a DIFFERENT exception type than the connection-error
    # test above -- confirms the broad except catches whatever AgentEndpoint
    # can raise (timeout, malformed-response KeyError, exhausted-retries
    # HTTPError, ...), not just the one most obvious case.
    endpoint = _mock_endpoint()
    endpoint.chat.side_effect = KeyError("response")
    adapter = HTTPAgentAdapter(endpoint)

    result = adapter.send("direct", "hi")

    assert result.is_synthetic is True
    assert "KeyError" in result.final_text


def test_endpoint_attribute_is_the_same_object_passed_in():
    # This is the exact seam Slice B's deep-attack bridge reaches through
    # to share ONE AgentEndpoint (and therefore one requests.Session)
    # between the campaign/planner side and a wrapped BaseAttack subclass.
    endpoint = _mock_endpoint()
    adapter = HTTPAgentAdapter(endpoint)

    assert adapter.endpoint is endpoint


def test_ground_truth_mission_achieved_is_stubbed_false():
    # Explicit Phase 2 decision (Open Question 5), not an oversight --
    # see this method's own docstring for the accepted consequence.
    adapter = HTTPAgentAdapter(_mock_endpoint())
    assert adapter.ground_truth_mission_achieved() is False
