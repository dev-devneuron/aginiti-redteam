"""Regression test locking in the exp30 offline validation's own finding:
`aginiti/graph/novelty.py`'s 2026-08-14 `PROACTIVE_COVERAGE_BONUS` fix
causally improves cross-family coverage at a tight budget, isolated from
every other utility term (see `aginiti/operators/family_coverage_
scenario_definitions.py`'s own docstring for the two earlier, rejected
scenario designs and why each accidentally tested something else).

At budget=10 (comfortably inside the 15-member `family_a`'s own size, so
nothing here is explained by "it simply ran out of family_a options"):
pre-fix code and the fully non-adaptive `StaticPolicy` checklist BOTH
never touch the untried `family_b` at all; post-fix code always does, on
the very first opportunity, while continuing to find the one real
`family_a` finding just as reliably as before (this fix is additive --
"informs, never vetoes," matching the project's own established
discipline for every planner utility term; it never trades away
reliability at the thing pre-fix code was already good at)."""
from __future__ import annotations

import aginiti.graph.novelty as nv
from aginiti.campaign import run_campaign
from aginiti.graph.attack_category import operator_primary_family
from aginiti.graph.schema import RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.family_coverage_scenario_definitions import build_family_coverage_library
from aginiti.operators.library import OperatorLibrary
from aginiti.planner.aginiti_planner import AginitiPlanner
from aginiti.policies.aginiti_policy import AginitiPolicy
from aginiti.policies.static_policy import StaticPolicy
from aginiti.target.family_coverage_scenario_agent import FamilyCoverageScenarioAgent

_TIGHT_BUDGET = 10  # inside family_a's own 15-member size -- see module docstring


def _pre_fix_term(attack_category, belief):
    """The exact pre-2026-08-14 family_diversification_term() body -- see
    experiments/exp30_offline_planner_fix_validation.py's own copy of
    this, kept in sync manually since the original no longer exists in
    novelty.py to import from."""
    if attack_category is None:
        return 0.0
    stats = belief.family(attack_category)
    if stats.looks_saturated:
        extra_attempts = stats.confirmed_total - 1
        penalty = min(nv.MAX_SATURATION_PENALTY, nv.SATURATION_PENALTY_PER_EXTRA_ATTEMPT * extra_attempts)
        return -penalty
    if stats.attempted == 0:
        any_other_saturated = any(
            other.looks_saturated for name, other in belief.family_stats.items() if name != attack_category
        )
        if any_other_saturated:
            return nv.DIVERSIFICATION_BONUS
        return 0.0
    return 0.0


def _run(policy, budget=_TIGHT_BUDGET):
    mission = Mission(goal="test", success_criteria=("__unreachable__",), budget=budget,
                       risk_threshold=RiskTier.MEDIUM, success_mode="any")
    library = OperatorLibrary(build_family_coverage_library())
    agent = FamilyCoverageScenarioAgent()
    result = run_campaign(mission=mission, library=library, agent=agent, policy=policy,
                           ssg=SecurityStateGraph(), max_steps=budget, stop_on_mission_success=True)
    families = {operator_primary_family(library.get(op_id)) for op_id in result.operators_executed}
    return result, agent, families


def test_pre_fix_code_never_touches_the_second_family_within_a_tight_budget():
    real_term = nv.family_diversification_term
    nv.family_diversification_term = _pre_fix_term
    try:
        planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)
        result, agent, families = _run(AginitiPolicy(planner))
    finally:
        nv.family_diversification_term = real_term

    assert families == {"direct_prompt_attack"}
    assert not any(op.startswith("family_b_probe") for op in result.operators_executed)
    # It still reliably found the one real family_a finding -- the bug was
    # narrowness, never unreliability.
    assert agent.distinct_secrets_found() == 1


def test_post_fix_code_touches_both_families_within_the_same_tight_budget():
    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)
    result, agent, families = _run(AginitiPolicy(planner))

    assert families == {"direct_prompt_attack", "encoding_attack"}
    assert any(op.startswith("family_b_probe") for op in result.operators_executed)
    # And it did NOT trade away the reliable family_a finding to get there.
    assert agent.distinct_secrets_found() == 1


def test_post_fix_samples_the_second_family_as_its_very_next_pick():
    """Not just "eventually" -- the fix's whole point is an EARLY foothold
    in a second family, not a late one."""
    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)
    result, _, _ = _run(AginitiPolicy(planner))
    assert result.operators_executed[1].startswith("family_b_probe")


def test_static_checklist_also_never_reaches_the_second_family_at_this_budget():
    """Confirms the pre-fix behavior wasn't uniquely bad -- it was exactly
    as narrow as a fully non-adaptive, no-intelligence checklist enumerator,
    which is the real, disclosed severity of the bug this fix closes."""
    result, agent, families = _run(StaticPolicy())
    assert families == {"direct_prompt_attack"}
    assert agent.distinct_secrets_found() == 1
