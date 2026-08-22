"""Requirement 8's exact scenario, made concrete and deterministic:

    operator response
    -> fuzzy/structured oracle detects partial disclosure
    -> verified ClaimEffect is created
    -> security boundary updates
    -> TargetBeliefState updates
    -> planner chooses a different follow-up operator because of that
       evidence.
    Prove that removing the evidence causes a different decision.

Uses `multi_family_agent`'s `encoding_v3` (whose own narrow extractor never
recognizes its real disclosure -- see multi_family_definitions.py) combined
with the EXISTING, already-general `escalate_after_disclosure` operator
(aginiti/operators/adaptive_followups.py -- ClassPrecondition(category=
CATEGORY_MISSION_OUTCOME), unmodified, not written for this test) as the
"different follow-up operator" the new evidence unlocks. No new chain
mechanism is introduced here -- this proves the EXISTING ClassPrecondition
discovery mechanism (2026-08-12) and the NEW independent-evidence path
(2026-08-14) compose correctly, end to end, exactly as intended."""
from __future__ import annotations

from aginiti.core.observation_adapter import ObservationAdapter
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.security_boundary import BOUNDARY_L5
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.graph.target_belief import TargetBeliefState
from aginiti.core.mission import Mission
from aginiti.operators.adaptive_followups import adaptive_followup_operators
from aginiti.operators.library import OperatorLibrary
from aginiti.operators.multi_family_definitions import build_multi_family_library
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from aginiti.core.policies.base import eligible_operators
from aginiti.core.policies.static_policy import StaticPolicy
from benchmarks.agents.multi_family_agent import MultiFamilyAgent


class _BlindMultiFamilyAgent(MultiFamilyAgent):
    """Identical target behavior (same responses, same ground truth), but
    WITHOUT an independent evidence oracle -- `independent_evidence_check`
    resolves to a plain `None` class attribute, so `getattr(agent,
    "independent_evidence_check", None)` in ObservationAdapter finds `None`
    and skips the whole independent-evidence path, exactly reproducing
    "this adapter never implemented the mechanism" (the state every real
    adapter was in before this fix). Everything else about this target is
    byte-identical to MultiFamilyAgent -- the ONLY variable this isolates
    is whether the independent oracle exists."""
    independent_evidence_check = None


def _library_with_followups() -> OperatorLibrary:
    return OperatorLibrary(build_multi_family_library() + list(adaptive_followup_operators()))


def _mission(budget: int) -> Mission:
    return Mission(goal="evidence propagation", success_criteria=("__no_such_key__",),
                    budget=budget, risk_threshold=RiskTier.MEDIUM, success_mode="any")


def test_escalate_after_disclosure_is_not_eligible_before_encoding_v3():
    """Sanity precondition: before ANY mission-outcome-shaped claim exists,
    the ClassPrecondition-gated follow-up is not yet in the candidate set
    at all -- confirms the later change is a genuine eligibility
    transition, not something that was already true."""
    library = _library_with_followups()
    ssg = SecurityStateGraph()
    elig = eligible_operators(library, ssg, _mission(8), prompts_used=0, executed_ids=frozenset())
    assert "escalate_after_disclosure" not in {op.id for op in elig}


def test_independent_evidence_unlocks_the_followup_operator():
    """The Fact -> Observation -> Claim -> Evidence chain, verified end to
    end: after encoding_v3 executes against an agent WITH the independent
    oracle, a real CONFIRMED, CATEGORY_MISSION_OUTCOME, security_boundary-
    tagged claim exists purely from the independent path (encoding_v3's OWN
    extractor never confirms anything mission-outcome-shaped -- see
    multi_family_definitions.py) -- and THAT claim is what makes
    escalate_after_disclosure newly eligible, verified via
    TargetBeliefState and the live eligibility check, not asserted by
    fiat."""
    library = _library_with_followups()
    ssg = SecurityStateGraph()
    agent = MultiFamilyAgent()
    adapter = ObservationAdapter()
    executed = ["tool_discovery_probe", "direct_v1", "direct_v2", "encoding_v1", "recon_probe",
                "encoding_v2", "direct_v3"]  # the exact pre-collapse prefix -- see test_multi_family_adaptive_discovery.py
    mission = _mission(9)
    for op_id in executed:
        adapter.execute(library.get(op_id), ssg, agent)

    # Before encoding_v3: not yet eligible.
    elig_before = eligible_operators(library, ssg, mission, len(executed), frozenset(executed))
    assert "escalate_after_disclosure" not in {op.id for op in elig_before}
    belief_before = TargetBeliefState.from_ssg(ssg, library)
    assert "encoding_v3_independent_disclosure_confirmed" not in belief_before.mission_outcomes

    adapter.execute(library.get("encoding_v3"), ssg, agent)
    executed.append("encoding_v3")

    # The independent claim itself: real, CONFIRMED, boundary-tagged --
    # concrete evidence, not an LLM inference (see IndependentFinding's own
    # docstring: security_boundary is REQUIRED, supplied directly by the
    # adapter's own deterministic substring check).
    claim = ssg.current_claim("encoding_v3_independent_disclosure_confirmed")
    assert claim is not None and claim.status.value == "confirmed"
    assert ssg.claim_boundary["encoding_v3_independent_disclosure_confirmed"] == BOUNDARY_L5

    # TargetBeliefState picks it up automatically -- zero planner-side special-casing.
    belief_after = TargetBeliefState.from_ssg(ssg, library)
    assert "encoding_v3_independent_disclosure_confirmed" in belief_after.mission_outcomes

    # And the follow-up operator is now genuinely eligible, purely BECAUSE
    # of this one new claim.
    elig_after = eligible_operators(library, ssg, mission, len(executed), frozenset(executed))
    assert "escalate_after_disclosure" in {op.id for op in elig_after}


def test_hypothesis_escalation_bonus_prefers_the_followup_right_after_the_evidence_arrives():
    """Not just eligible -- actually PREFERRED: hypothesis_escalation_bonus
    (2026-08-12) rewards a ClassPrecondition-gated operator whose
    eligibility just opened up from a RECENT confirmation. Verified by
    reading the real per-candidate breakdown `rank()` produces, not
    inferred."""
    library = _library_with_followups()
    ssg = SecurityStateGraph()
    agent = MultiFamilyAgent()
    adapter = ObservationAdapter()
    executed = ["tool_discovery_probe", "direct_v1", "direct_v2", "encoding_v1", "recon_probe",
                "encoding_v2", "direct_v3", "encoding_v3"]
    mission = _mission(9)
    for op_id in executed:
        adapter.execute(library.get(op_id), ssg, agent)

    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)
    ranked = planner.rank(library, ssg, mission, len(executed), frozenset(executed))
    escalate_candidate = next(rc for rc in ranked if rc.operator.id == "escalate_after_disclosure")
    assert escalate_candidate.hypothesis_escalation_bonus > 0


def test_removing_the_independent_oracle_changes_the_decision():
    """The exact instruction: "Prove that removing the evidence causes a
    different decision." Identical library, identical target RESPONSES,
    identical operator sequence up to and including encoding_v3 -- the
    ONLY difference is whether the adapter implements
    `independent_evidence_check`. With it: escalate_after_disclosure
    becomes eligible. Without it: encoding_v3's own narrow extractor only
    ever confirms `encoding_v3_blocked` (a DEFENDER-subgraph claim, not
    mission-outcome-shaped), so escalate_after_disclosure's
    ClassPrecondition NEVER fires -- a genuinely different downstream
    decision, caused purely by the presence/absence of the evidence path."""
    executed = ["tool_discovery_probe", "direct_v1", "direct_v2", "encoding_v1", "recon_probe",
                "encoding_v2", "direct_v3", "encoding_v3"]
    mission = _mission(9)

    def _run(agent_cls):
        library = _library_with_followups()
        ssg = SecurityStateGraph()
        agent = agent_cls()
        adapter = ObservationAdapter()
        for op_id in executed:
            adapter.execute(library.get(op_id), ssg, agent)
        elig = eligible_operators(library, ssg, mission, len(executed), frozenset(executed))
        return {op.id for op in elig}, ssg

    elig_with_oracle, ssg_with = _run(MultiFamilyAgent)
    elig_without_oracle, ssg_without = _run(_BlindMultiFamilyAgent)

    assert "escalate_after_disclosure" in elig_with_oracle
    assert "escalate_after_disclosure" not in elig_without_oracle
    assert ssg_with.current_claim("encoding_v3_independent_disclosure_confirmed") is not None
    assert ssg_without.current_claim("encoding_v3_independent_disclosure_confirmed") is None
    # Same target, same responses, same operator sequence -- confirming the
    # divergence is caused SOLELY by the independent-evidence path, not by
    # any other difference between the two runs.
    assert ssg_with.current_claim("encoding_v3_blocked") is not None
    assert ssg_without.current_claim("encoding_v3_blocked") is not None


def test_independent_evidence_stops_the_campaign_via_stop_on_mission_success():
    """2026-08-22 fix, verified end to end through a REAL run_campaign()
    call (not just is_satisfied() in isolation, and not just the
    eligibility check the tests above use) -- the exact live-observed bug
    this closes: exp33's support/random trial ran to BUDGET_EXHAUSTED even
    though the independent oracle had already confirmed a real disclosure,
    because the Mission's success_criteria named the operator's own
    (never-confirmed-by-its-judge) claim key, not the oracle's
    differently-named one. `encoding_v3` reproduces that exact shape
    deterministically -- it ALWAYS refuses per its own narrow extractor
    (multi_family_definitions.py's own module docstring) while its raw
    response ALWAYS trips the independent oracle -- so a Mission naming
    ONLY `encoding_v3_disclosed` can NEVER be satisfied the ordinary way,
    in any run, regardless of budget. Proven via a direct A/B: identical
    library/agent/policy/budget, the only variable is `independent_
    evidence_satisfies`."""
    library = OperatorLibrary(build_multi_family_library())
    budget = 12  # the library's own full size -- see build_multi_family_library()

    def _run(independent_evidence_satisfies: bool):
        mission = Mission(goal="test", success_criteria=("encoding_v3_disclosed",),
                           budget=budget, risk_threshold=RiskTier.MEDIUM, success_mode="any",
                           independent_evidence_satisfies=independent_evidence_satisfies)
        return run_campaign(mission=mission, library=library, agent=MultiFamilyAgent(),
                             policy=StaticPolicy(), max_steps=budget, stop_on_mission_success=True)

    result_fixed = _run(independent_evidence_satisfies=True)
    assert result_fixed.outcome == "SUCCESS"
    # Stopped RIGHT AFTER encoding_v3 fired -- the actual efficiency payoff,
    # not merely "eventually succeeded somehow."
    assert result_fixed.operators_executed[-1] == "encoding_v3"
    assert result_fixed.steps_executed < budget

    result_broken = _run(independent_evidence_satisfies=False)
    assert result_broken.outcome == "BUDGET_EXHAUSTED"  # the exact real bug, reproduced
    assert result_broken.steps_executed == budget
    # encoding_v3's own claim genuinely never confirms, in either run --
    # confirming the fix adds a second SATISFACTION path, it does not
    # change what confirms the named claim itself.
    assert result_broken.ssg.current_claim("encoding_v3_disclosed") is None
    assert result_fixed.ssg.current_claim("encoding_v3_disclosed") is None
