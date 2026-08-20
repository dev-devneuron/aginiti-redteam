"""Regression tests for the agentic-primitives pack (Issue 3 of the
2026-08-12 architectural directive) -- the pytest counterpart to
experiments/agentic_primitives_dry_run.py. Proves the two new primitive
types (approval gate, untrusted tool-output content) compose correctly via
Issue 1's ClassPrecondition mechanism in a SECOND, independently-authored
operator pack, and that a blocked approval-gate bypass is recorded with a
real, structured failure_diagnosis (Issue 4)."""
from __future__ import annotations

from dataclasses import dataclass, field

from aginiti.adapters.base import SendResult
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.failure_diagnosis import BLOCKED_BY_APPROVAL_GATE
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.security_boundary import BOUNDARY_L3
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.agentic_primitives_definitions import build_agentic_primitives_library
from aginiti.core.policies.aginiti_policy import AginitiPolicy


@dataclass
class _EchoAdapter:
    ssg: SecurityStateGraph
    mission_key: str
    suppressed_claim_keys: frozenset = field(default_factory=frozenset)

    def send(self, channel: str, prompt: str) -> SendResult:
        suppressed_prompts = {f"__confirmed__{key}" for key in self.suppressed_claim_keys}
        return SendResult(final_text="" if prompt in suppressed_prompts else prompt)

    def ground_truth_mission_achieved(self) -> bool:
        return self.ssg.is_confirmed(self.mission_key)


def _mission() -> Mission:
    return Mission(goal="agentic primitives test", success_criteria=("agentic_approval_gate_bypassed",),
                    budget=12, risk_threshold=RiskTier.LOW, constraints=())


def test_no_operator_past_stage_1_uses_an_exact_key_precondition():
    library = build_agentic_primitives_library()
    entry_points = {"agentic_discover_capability"}
    for op in library:
        if op.id in entry_points:
            continue
        assert op.preconditions == (), f"{op.id} should have no exact-key preconditions"
        assert len(op.precondition_classes) >= 1, f"{op.id} should be class-gated"


def test_full_chain_succeeds_and_reaches_l3():
    ssg = SecurityStateGraph()
    library = build_agentic_primitives_library()
    mission = _mission()
    agent = _EchoAdapter(ssg=ssg, mission_key="agentic_approval_gate_bypassed")

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=12, ssg=ssg)

    assert result.outcome == "SUCCESS"
    assert ssg.is_confirmed("agentic_approval_gate_bypassed")
    assert agent.ground_truth_mission_achieved()
    assert ssg.highest_boundary_crossed() == BOUNDARY_L3
    # Both new primitive types actually fired.
    assert "agentic_untrusted_tool_output_instruction_followed" in result.operators_executed
    assert "agentic_approval_gate_bypass_attempt" in result.operators_executed


def test_blocked_approval_gate_records_a_structured_generalizable_diagnosis():
    ssg = SecurityStateGraph()
    library = build_agentic_primitives_library()
    mission = _mission()
    agent = _EchoAdapter(ssg=ssg, mission_key="agentic_approval_gate_bypassed",
                          suppressed_claim_keys=frozenset({"agentic_approval_gate_bypassed"}))

    run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=12, ssg=ssg)

    diagnoses = ssg.confirmed_failure_diagnoses()
    assert diagnoses.get("agentic_approval_gate_enforced") == BLOCKED_BY_APPROVAL_GATE


def test_either_trust_operator_unlocks_the_same_downstream_primitives():
    """Same discovery proof as Issue 1's original demo, exercised again on
    an independent pack: delete either trust operator (by suppressing its
    marker) and the SAME downstream tool-output/approval-gate chain still
    completes through the other, unchanged."""
    for suppressed_key in ("agentic_trust_session", "agentic_trust_role"):
        ssg = SecurityStateGraph()
        library = build_agentic_primitives_library()
        mission = _mission()
        agent = _EchoAdapter(ssg=ssg, mission_key="agentic_approval_gate_bypassed",
                              suppressed_claim_keys=frozenset({suppressed_key}))
        result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=12, ssg=ssg)
        assert result.outcome == "SUCCESS", f"chain should still complete with {suppressed_key} suppressed"
