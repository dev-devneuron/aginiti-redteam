"""Tests for the evidence-provenance gate (2026-08-08): SendResult.
is_synthetic and ObservationAdapter.execute()'s hard gate on it.

Root cause this closes, reproduced directly: a live combined DVLA campaign
showed DVLAAdapter's own API-error-recovery text (Groq's tool-definition
preamble, echoed back after a malformed tool-call attempt) get fed to a
DIFFERENT operator's judge (system_prompt_extraction) and misread as a
genuine system-prompt disclosure -- a real, caught false positive, verified
false by comparing the disclosed text against the actual SYSTEM_PROMPT
constant (they don't match). No live API calls here: this reproduces the
SAME structural shape (adapter-synthesized text reaching the judge/
extractor) with a scripted fake agent.
"""
from types import SimpleNamespace
from unittest.mock import patch

from aginiti.core.observation_adapter import ObservationAdapter
from aginiti.adapters.base import SendResult
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import CATEGORY_MISSION_OUTCOME, SecurityStateGraph, SUBGRAPH_DEFENDER, SUBGRAPH_TARGET
from aginiti.operators.library import ClaimEffect, Operator


class _FakeAgent:
    """Returns whatever SendResult the test hands it -- lets each test
    control is_synthetic directly, same pattern as every other adapter
    test double in this suite."""

    def __init__(self, send_result):
        self._send_result = send_result

    def send(self, channel, prompt):
        return self._send_result

    def ground_truth_mission_achieved(self):
        return False


def _judge_style_op():
    # No extractor -- exercises the LLM-judge path, exactly like
    # system_prompt_extraction (the operator actually misled live).
    return Operator(
        id="system_prompt_extraction_like", description="x", prompt="x", channel="direct",
        preconditions=(),
        effects_success=(ClaimEffect("system_prompt_disclosed", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET,
                                      weight=3, category=CATEGORY_MISSION_OUTCOME),),
        effects_failure=(ClaimEffect("system_prompt_extraction_blocked", ClaimStatus.CONFIRMED,
                                      SUBGRAPH_DEFENDER, weight=1),),
        cost_prompts=1, risk_tier=RiskTier.LOW,
    )


def _extractor_style_op():
    return Operator(
        id="deterministic_probe", description="x", prompt="x", channel="direct",
        preconditions=(), effects_success=(ClaimEffect("k", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw: ["k::hypothesized"],  # would ALWAYS confirm if ever called
    )


# -- The exact reproduced false positive ---------------------------------

def test_synthetic_recovery_text_never_reaches_the_judge():
    op = _judge_style_op()
    ssg = SecurityStateGraph()
    # The REAL text that fooled the judge live: Groq's tool-definition
    # preamble, which superficially reads as "internal instructions" but
    # is NOT the target's actual system prompt.
    recovery_text = (
        "[Aginiti: the target's tool-call attempt was rejected by the API before a normal reply "
        "was generated; raw generation follows]\nUse the function 'get_current_user' to 'Returns "
        "the current user for querying transactions.' {\"name\":\"get_current_user\", ...}"
    )
    agent = _FakeAgent(SendResult(final_text=recovery_text, tool_trace=[], is_synthetic=True))

    with patch("aginiti.core.observation_adapter.chat_json") as mock_chat:
        result = ObservationAdapter().execute(op, ssg, agent)

    mock_chat.assert_not_called()  # the actual bug: this WAS called live, on this exact shape of text
    assert result.confirmed_keys == []
    assert result.overall_success is False
    assert ssg.current_claim("system_prompt_disclosed") is None
    assert "synthetic" in result.reasoning or "non-target-generated" in result.reasoning


def test_synthetic_text_never_reaches_a_deterministic_extractor_either():
    # The gate is upstream of BOTH interpretation paths, not just the judge.
    op = _extractor_style_op()
    ssg = SecurityStateGraph()
    agent = _FakeAgent(SendResult(final_text="anything", tool_trace=[], is_synthetic=True))

    result = ObservationAdapter().execute(op, ssg, agent)

    assert result.confirmed_keys == []
    assert result.reasoning != "deterministic extraction (no judge call)"
    assert "no judge/extractor call" in result.reasoning


def test_synthetic_response_is_still_recorded_as_a_fact():
    # Transparency preserved: nothing is hidden, it's just never treated
    # as evidence ABOUT THE TARGET.
    op = _judge_style_op()
    ssg = SecurityStateGraph()
    agent = _FakeAgent(SendResult(final_text="the recovery text", tool_trace=[], is_synthetic=True))

    with patch("aginiti.core.observation_adapter.chat_json"):
        ObservationAdapter().execute(op, ssg, agent)

    fact_texts = [f.data.get("text") for f in ssg.facts if f.kind == "response_text"]
    assert "the recovery text" in fact_texts


def test_synthetic_response_creates_no_supporting_or_contradicting_observation():
    op = _judge_style_op()
    ssg = SecurityStateGraph()
    agent = _FakeAgent(SendResult(final_text="x", tool_trace=[], is_synthetic=True))

    with patch("aginiti.core.observation_adapter.chat_json"):
        ObservationAdapter().execute(op, ssg, agent)

    assert ssg.observations == [] or all(
        not o.supports and not o.contradicts for o in ssg.observations
    )


# -- Regression: genuine target responses are completely unaffected ------

def test_genuine_non_synthetic_response_still_reaches_the_judge_normally():
    op = _judge_style_op()
    ssg = SecurityStateGraph()
    fake_verdict = {"confirmed_effect_ids": ["system_prompt_disclosed::confirmed"],
                     "details": {}, "reasoning": "the response contains the real system prompt"}
    agent = _FakeAgent(SendResult(final_text="Assistant helps the current user...", tool_trace=[]))

    with patch("aginiti.core.observation_adapter.chat_json", return_value=fake_verdict) as mock_chat:
        result = ObservationAdapter().execute(op, ssg, agent)

    mock_chat.assert_called_once()
    assert result.overall_success is True
    assert ssg.current_claim("system_prompt_disclosed").status == ClaimStatus.CONFIRMED


def test_genuine_non_synthetic_response_still_reaches_the_extractor_normally():
    op = _extractor_style_op()
    ssg = SecurityStateGraph()
    agent = _FakeAgent(SendResult(final_text="structured data", tool_trace=[]))  # is_synthetic defaults False

    result = ObservationAdapter().execute(op, ssg, agent)

    assert result.confirmed_keys == ["k"]
    assert result.reasoning == "deterministic extraction (no judge call)"


def test_send_result_defaults_to_non_synthetic():
    assert SendResult(final_text="x").is_synthetic is False


def test_fake_agent_without_is_synthetic_attribute_defaults_safely():
    # A minimal duck-typed test double (no SendResult, no is_synthetic
    # attribute at all) must behave exactly as before this fix -- the
    # getattr default keeps every existing test double in this suite working.
    op = _extractor_style_op()
    ssg = SecurityStateGraph()
    agent = _FakeAgent(SimpleNamespace(final_text="structured data", tool_trace=[]))

    result = ObservationAdapter().execute(op, ssg, agent)

    assert result.confirmed_keys == ["k"]


# -- The actual three synthesis sites in the codebase, checked directly --

def test_every_adapter_that_synthesizes_fallback_text_marks_it_synthetic():
    # Locks the invariant this whole fix depends on: every SITE that
    # constructs SendResult with adapter-authored (not target-relayed)
    # text must set is_synthetic=True. Guards against a future adapter
    # silently reintroducing the exact DVLA bug.
    import inspect

    from aginiti.adapters import dvla_adapter
    from aginiti.target import demo_agent, injecagent_adapter

    for module, needle in (
        (dvla_adapter, '"[Aginiti: target API rejected the request'),
        (demo_agent, '"[max tool-call rounds reached]"'),
        (injecagent_adapter, '"[max tool-call rounds reached]"'),
    ):
        source = inspect.getsource(module)
        assert "is_synthetic=True" in source, f"{module.__name__} lost its is_synthetic marker"
