"""Tests for the deterministic-extractor bypass (Operator.extractor) --
"deterministic reasoning where possible": when set, ObservationAdapter
must skip the LLM judge entirely, not just ignore its output. No live API
calls.
"""
from types import SimpleNamespace
from unittest.mock import patch

from aginiti.adapter.observation_adapter import ObservationAdapter
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import SecurityStateGraph, SUBGRAPH_TARGET
from aginiti.operators.dvaa_definitions import _extract_mcp_tool_list
from aginiti.operators.library import ClaimEffect, Operator


class _FakeAgent:
    def __init__(self, text):
        self.text = text

    def send(self, channel, prompt):
        return SimpleNamespace(final_text=self.text, tool_trace=[])

    def ground_truth_mission_achieved(self):
        return False


def _op_with_extractor(extractor):
    return Operator(
        id="deterministic_probe", description="x", prompt="x", channel="direct",
        preconditions=(), effects_success=(ClaimEffect("k", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW, extractor=extractor,
    )


def test_extractor_set_skips_the_judge_entirely():
    op = _op_with_extractor(lambda raw: ["k::hypothesized"])
    ssg = SecurityStateGraph()

    with patch("aginiti.adapter.observation_adapter.chat_json") as mock_chat:
        result = ObservationAdapter().execute(op, ssg, _FakeAgent("some raw response"))

    mock_chat.assert_not_called()
    assert result.overall_success is True
    assert ssg.current_claim("k").status == ClaimStatus.HYPOTHESIZED
    assert result.reasoning == "deterministic extraction (no judge call)"


def test_extractor_confirming_nothing_yields_no_claims():
    op = _op_with_extractor(lambda raw: [])
    ssg = SecurityStateGraph()

    with patch("aginiti.adapter.observation_adapter.chat_json") as mock_chat:
        result = ObservationAdapter().execute(op, ssg, _FakeAgent("no match here"))

    mock_chat.assert_not_called()
    assert result.overall_success is False
    assert ssg.current_claim("k") is None


def test_operator_without_extractor_still_uses_the_judge():
    op = Operator(
        id="normal_probe", description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect("k", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )
    ssg = SecurityStateGraph()
    fake_verdict = {"confirmed_effect_ids": ["k::hypothesized"], "details": {}, "reasoning": "judged it"}

    with patch("aginiti.adapter.observation_adapter.chat_json", return_value=fake_verdict) as mock_chat:
        result = ObservationAdapter().execute(op, ssg, _FakeAgent("some raw response"))

    mock_chat.assert_called_once()
    assert result.reasoning == "judged it"


def test_extract_mcp_tool_list_confirms_when_tools_present():
    raw = '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file"}]}}'
    assert _extract_mcp_tool_list(raw) == ["mcp_tool_inventory_declared::hypothesized"]


def test_extract_mcp_tool_list_empty_when_no_tools():
    raw = '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'
    assert _extract_mcp_tool_list(raw) == []


def test_extract_mcp_tool_list_handles_malformed_json():
    assert _extract_mcp_tool_list("not json at all") == []


def test_extract_mcp_tool_list_handles_missing_result_key():
    assert _extract_mcp_tool_list('{"jsonrpc":"2.0","id":1}') == []
