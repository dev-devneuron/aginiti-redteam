"""Tests for aginiti/graph/decision_trace.py and its wiring into
aginiti/campaign.py -- proves a DecisionTrace is actually attached to
DecisionLogEntry.meta during a real (mock-target) campaign, and that its
`reason` text is built from real utility-breakdown numbers, not generated
prose."""
from aginiti.campaign import run_campaign
from aginiti.graph.decision_trace import DecisionTrace, build_decision_trace
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME, SecurityStateGraph
from aginiti.graph.target_belief import TargetBeliefState
from aginiti.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.planner.aginiti_planner import AginitiPlanner
from aginiti.policies.aginiti_policy import AginitiPolicy

CONFIRMED = ClaimStatus.CONFIRMED


class _StubAdapter:
    """Deterministic, no-LLM adapter: always confirms an operator's first
    success effect. Enough to drive a real campaign end-to-end offline."""

    def __init__(self):
        self.calls = 0

    def send(self, channel, prompt):
        from aginiti.adapters.base import SendResult
        self.calls += 1
        return SendResult(final_text=f"response #{self.calls} to: {prompt[:60]}")

    def ground_truth_mission_achieved(self):
        return False


def _op(op_id: str, key: str, weight: int = 3) -> Operator:
    return Operator(
        id=op_id, description=f"test op {op_id}", prompt=f"do {op_id}", channel="direct",
        preconditions=(), effects_success=(ClaimEffect(key, CONFIRMED, weight=weight, category=CATEGORY_MISSION_OUTCOME),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw: [f"{key}::confirmed"],
    )


def test_build_decision_trace_reason_reflects_real_meta_values():
    trace = build_decision_trace(
        step=1, ssg=SecurityStateGraph(), chosen_operator_id="my_op",
        chosen_meta={"info_gain": 3.0, "business_impact": 0.5, "family_diversification": -0.8,
                     "hypothesis_escalation_bonus": 0.0, "alpha": 1.0, "beta": 0.0},
        last_fact_text="the target refused directly",
        family_diversification_active=True, hypothesis_escalation_active=False,
    )
    assert isinstance(trace, DecisionTrace)
    assert trace.selected_operator == "my_op"
    assert "info_gain=3.00" in trace.reason
    assert "-0.80" in trace.reason  # the demotion is visible, not hidden
    rendered = trace.render()
    assert rendered.startswith("Observation:")
    assert "Selected operator:\nmy_op" in rendered


def test_decision_trace_reflects_actual_belief_state_not_placeholder():
    ssg = SecurityStateGraph()
    ssg.record_fact("exec1", "response_text", {"text": "..."})
    ssg.claim_attack_category["capability_found"] = "low_value_reconnaissance"
    ssg.assert_claim("capability_found", "true", CONFIRMED, category="capability", subgraph="target")
    belief = TargetBeliefState.from_ssg(ssg)
    trace = build_decision_trace(
        step=2, ssg=ssg, chosen_operator_id="op2", chosen_meta={"info_gain": 1.0},
        last_fact_text="...", belief=belief,
    )
    assert "capability_found" in trace.updated_belief


def test_full_campaign_attaches_decision_trace_to_every_step():
    library = OperatorLibrary([_op("recon", "capability_found"), _op("follow_up", "secret_leaked")])
    mission = Mission(goal="test", success_criteria=("secret_leaked",), budget=5, risk_threshold=RiskTier.MEDIUM)
    result = run_campaign(mission=mission, library=library, agent=_StubAdapter(),
                           policy=AginitiPolicy(AginitiPlanner()), ssg=SecurityStateGraph(),
                           stop_on_mission_success=False)
    assert result.decision_log, "campaign should have taken at least one step"
    for entry in result.decision_log:
        assert "decision_trace" in entry.meta, f"step {entry.step} has no decision_trace"
        rendered = entry.meta["decision_trace"]
        assert "Selected operator:" in rendered
        assert entry.chosen_operator_id in rendered


def test_baseline_policies_do_not_get_a_decision_trace():
    from aginiti.policies.random_policy import RandomPolicy

    library = OperatorLibrary([_op("recon", "capability_found")])
    mission = Mission(goal="test", success_criteria=("capability_found",), budget=3, risk_threshold=RiskTier.MEDIUM)
    result = run_campaign(mission=mission, library=library, agent=_StubAdapter(),
                           policy=RandomPolicy(seed=1), ssg=SecurityStateGraph())
    assert result.decision_log
    for entry in result.decision_log:
        assert "decision_trace" not in entry.meta
