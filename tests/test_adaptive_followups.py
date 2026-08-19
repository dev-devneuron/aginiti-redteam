"""Tests for aginiti/operators/adaptive_followups.py -- proves the two
ClassPrecondition-gated follow-ups genuinely become eligible off of
WHATEVER upstream operator produces a matching claim (not one hardcoded
predecessor), and that a full campaign actually chains through them."""
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import CATEGORY_DEFENDER_CONTROL, CATEGORY_MISSION_OUTCOME, SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.adaptive_followups import adaptive_followup_operators
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from aginiti.core.policies.aginiti_policy import AginitiPolicy

CONFIRMED = ClaimStatus.CONFIRMED


def _disclosure_op(op_id: str, key: str) -> Operator:
    """A generic 'something got disclosed' operator -- deliberately NOT
    named anything adaptive_followups.py references directly."""
    return Operator(
        id=op_id, description="x", prompt="x", channel="direct",
        preconditions=(),
        effects_success=(ClaimEffect(key, CONFIRMED, weight=3, category=CATEGORY_MISSION_OUTCOME),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw: [f"{key}::confirmed"],
    )


def _refusal_op(op_id: str, key: str) -> Operator:
    return Operator(
        id=op_id, description="x", prompt="x", channel="direct",
        preconditions=(), effects_success=(),
        effects_failure=(ClaimEffect(key, CONFIRMED, weight=1, category=CATEGORY_DEFENDER_CONTROL),),
        cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw: [f"{key}::confirmed"],
    )


class _StubAdapter:
    def send(self, channel, prompt):
        from aginiti.adapters.base import SendResult
        return SendResult(final_text="stub response")

    def ground_truth_mission_achieved(self):
        return False


def test_escalate_after_disclosure_ineligible_before_any_disclosure():
    ssg = SecurityStateGraph()
    ops = adaptive_followup_operators()
    escalate = next(o for o in ops if o.id == "escalate_after_disclosure")
    assert escalate.preconditions_met(ssg) is False


def test_escalate_after_disclosure_becomes_eligible_from_an_unrelated_operator():
    """The point: eligibility comes from ANY confirmed mission_outcome
    claim, not one named predecessor."""
    ssg = SecurityStateGraph()
    ssg.claim_category["totally_unrelated_leak"] = CATEGORY_MISSION_OUTCOME
    ssg.assert_claim("totally_unrelated_leak", "true", CONFIRMED, category=CATEGORY_MISSION_OUTCOME)

    ops = adaptive_followup_operators()
    escalate = next(o for o in ops if o.id == "escalate_after_disclosure")
    assert escalate.preconditions_met(ssg) is True


def test_pivot_after_refusal_becomes_eligible_from_any_confirmed_block():
    ssg = SecurityStateGraph()
    ssg.claim_category["some_probe_blocked"] = CATEGORY_DEFENDER_CONTROL
    ssg.assert_claim("some_probe_blocked", "true", CONFIRMED, category=CATEGORY_DEFENDER_CONTROL)

    ops = adaptive_followup_operators()
    pivot = next(o for o in ops if o.id == "pivot_after_refusal")
    assert pivot.preconditions_met(ssg) is True


def test_full_campaign_chains_through_escalate_after_disclosure():
    """A real 2-step discovery: op1 (generic, no relation to
    adaptive_followups.py) confirms a disclosure; escalate_after_disclosure
    is not eligible at step 0 but becomes eligible and gets picked at
    step 1+ purely from the semantic tag, with zero hardcoded reference
    between the two operators. The real operator is judge-based (no
    extractor -- designed for real live-campaign use); this test swaps in
    a deterministic extractor via dataclasses.replace() purely so the
    outcome is checkable with zero LLM calls, same pattern
    injecagent_pool.py already uses for a similar reason."""
    import dataclasses

    escalate, pivot = adaptive_followup_operators()
    escalate = dataclasses.replace(escalate, extractor=lambda raw: ["escalated_disclosure_confirmed::confirmed"])
    library = OperatorLibrary([
        _disclosure_op("op1_unrelated_leak", "some_leak_confirmed"),
        escalate, pivot,
    ])
    mission = Mission(goal="test", success_criteria=("escalated_disclosure_confirmed",),
                       budget=5, risk_threshold=RiskTier.MEDIUM)
    result = run_campaign(mission=mission, library=library, agent=_StubAdapter(),
                           policy=AginitiPolicy(AginitiPlanner()), ssg=SecurityStateGraph(),
                           stop_on_mission_success=False)
    assert "op1_unrelated_leak" in result.operators_executed
    assert "escalate_after_disclosure" in result.operators_executed
    assert result.outcome == "SUCCESS"
