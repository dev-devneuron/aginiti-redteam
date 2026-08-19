"""Tests that a confirmed DEFENDER-subgraph effect actually increments the
target's suspicion counter -- the mechanism that makes the environment
punish burning failed attempts, not just something logged for show."""
from unittest.mock import patch

from aginiti.adapter.observation_adapter import ObservationAdapter
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import SUBGRAPH_DEFENDER, SUBGRAPH_TARGET, SecurityStateGraph
from aginiti.operators.library import ClaimEffect, Operator
from aginiti.target.demo_agent import DemoAgent


def _blocked_operator() -> Operator:
    return Operator(
        id="risky_probe", description="risky probe", prompt="do the risky thing",
        channel="direct", preconditions=(),
        effects_success=(ClaimEffect("mission_x", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET),),
        effects_failure=(ClaimEffect("filter_present", ClaimStatus.CONFIRMED, SUBGRAPH_DEFENDER),),
        cost_prompts=1, risk_tier=RiskTier.LOW,
    )


def test_confirmed_defender_effect_increments_suspicion():
    op = _blocked_operator()
    ssg = SecurityStateGraph()
    agent = DemoAgent()

    fake_verdict = {"confirmed_effect_ids": ["filter_present::confirmed"], "details": {}, "reasoning": "blocked"}
    with patch("aginiti.adapter.observation_adapter.chat_json", return_value=fake_verdict), \
         patch.object(DemoAgent, "send", return_value=type("R", (), {"final_text": "blocked", "tool_trace": []})()):
        result = ObservationAdapter().execute(op, ssg, agent)

    assert result.overall_success is False
    assert agent.world.suspicion_level == 1


def test_confirmed_success_effect_does_not_increment_suspicion():
    op = _blocked_operator()
    ssg = SecurityStateGraph()
    agent = DemoAgent()

    fake_verdict = {"confirmed_effect_ids": ["mission_x::confirmed"], "details": {}, "reasoning": "worked"}
    with patch("aginiti.adapter.observation_adapter.chat_json", return_value=fake_verdict), \
         patch.object(DemoAgent, "send", return_value=type("R", (), {"final_text": "ok", "tool_trace": []})()):
        result = ObservationAdapter().execute(op, ssg, agent)

    assert result.overall_success is True
    assert agent.world.suspicion_level == 0
