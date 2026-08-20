"""Tests for aginiti/graph/novelty.py's technique_cluster_diversification_
term() (2026-08-14) -- the second, WITHIN-family fix, separate from
family_diversification_term. Two layers: pure-function unit tests (mirrors
tests/test_novelty.py's own structure) plus a full-campaign regression
test locking in exp31's own offline validation finding."""
from __future__ import annotations

from aginiti.core.campaign import run_campaign
from aginiti.core.graph.novelty import (
    CLUSTER_PENALTY_PER_ATTEMPT,
    MAX_CLUSTER_PENALTY,
    technique_cluster_diversification_term,
)
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.graph.target_belief import FamilyStats, TargetBeliefState
from aginiti.core.mission import Mission
from aginiti.operators.technique_cluster_scenario_definitions import build_technique_cluster_library
from aginiti.operators.library import OperatorLibrary
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from aginiti.core.policies.static_policy import StaticPolicy
from benchmarks.agents.technique_cluster_scenario_agent import TechniqueClusterScenarioAgent

_TIGHT_BUDGET = 5  # exactly the cluster's own size -- see technique_cluster_scenario_agent.py


def _belief(**cluster_stats: FamilyStats) -> TargetBeliefState:
    return TargetBeliefState(cluster_stats=dict(cluster_stats))


# --- pure-function unit tests ----------------------------------------------

def test_untagged_operator_is_always_a_no_op():
    belief = _belief(some_cluster=FamilyStats(attempted=5, confirmed_success=1))
    assert technique_cluster_diversification_term(None, belief) == 0.0


def test_a_clusters_first_ever_attempt_is_neutral_not_yet_redundant():
    belief = _belief()  # no entries at all -- cluster() falls back to the all-zero default
    assert technique_cluster_diversification_term("test_cluster", belief) == 0.0


def test_penalty_grows_with_every_additional_attempt_regardless_of_success():
    """The one real, disclosed way this differs from family_diversification_
    term: NOT success-immune. A cluster with 1 confirmed SUCCESS already in
    it still gets penalized for a 2nd/3rd/4th attempt -- diminishing
    returns on an ALREADY-ANSWERED hypothesis, not "family looks blocked."""
    one_attempt = _belief(test_cluster=FamilyStats(attempted=1, confirmed_success=1))
    two_attempts = _belief(test_cluster=FamilyStats(attempted=2, confirmed_success=1))
    three_attempts = _belief(test_cluster=FamilyStats(attempted=3, confirmed_success=1))

    p1 = technique_cluster_diversification_term("test_cluster", one_attempt)
    p2 = technique_cluster_diversification_term("test_cluster", two_attempts)
    p3 = technique_cluster_diversification_term("test_cluster", three_attempts)

    assert p1 < 0.0  # even a single prior attempt (a real success!) already discourages a repeat
    assert p2 <= p1  # grows (more negative) or stays capped
    assert p3 <= p2


def test_penalty_exact_formula_below_the_cap():
    belief = _belief(test_cluster=FamilyStats(attempted=1, confirmed_success=1))
    assert technique_cluster_diversification_term("test_cluster", belief) == -CLUSTER_PENALTY_PER_ATTEMPT


def test_penalty_caps_at_max_cluster_penalty():
    belief = _belief(test_cluster=FamilyStats(attempted=10, confirmed_success=1))
    assert technique_cluster_diversification_term("test_cluster", belief) == -MAX_CLUSTER_PENALTY


def test_a_family_wide_success_immune_family_diversification_is_a_separate_concern():
    """Sanity check on the module docstring's own central claim: this
    function's penalty fires purely off `attempted`, completely independent
    of confirmed_success -- an all-success cluster is penalized identically
    to an all-failure one with the same attempt count."""
    all_success = _belief(test_cluster=FamilyStats(attempted=3, confirmed_success=3))
    all_failure = _belief(test_cluster=FamilyStats(attempted=3, confirmed_blocked_other=3))
    assert (technique_cluster_diversification_term("test_cluster", all_success)
            == technique_cluster_diversification_term("test_cluster", all_failure))


# --- full-campaign regression test, locking in exp31's own finding --------

def _run(policy, budget=_TIGHT_BUDGET):
    mission = Mission(goal="test", success_criteria=("__unreachable__",), budget=budget,
                       risk_threshold=RiskTier.MEDIUM, success_mode="any")
    library = OperatorLibrary(build_technique_cluster_library())
    agent = TechniqueClusterScenarioAgent()
    result = run_campaign(mission=mission, library=library, agent=agent, policy=policy,
                           ssg=SecurityStateGraph(), max_steps=budget, stop_on_mission_success=True)
    return result, agent


def test_pre_fix_never_finds_the_singleton_within_a_tight_budget():
    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True,
                              enable_technique_cluster_diversification=False)
    result, agent = _run(AginitiPolicy(planner))
    assert not any(op.startswith("singleton_probe") for op in result.operators_executed)
    assert agent.distinct_findings_found() == 1


def test_post_fix_finds_both_real_findings_within_the_same_tight_budget():
    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True,
                              enable_technique_cluster_diversification=True)
    result, agent = _run(AginitiPolicy(planner))
    assert any(op.startswith("singleton_probe") for op in result.operators_executed)
    assert agent.distinct_findings_found() == 2
    assert agent.ground_truth_mission_achieved() is True


def test_static_checklist_also_never_reaches_the_singleton_at_this_budget():
    result, agent = _run(StaticPolicy())
    assert not any(op.startswith("singleton_probe") for op in result.operators_executed)
    assert agent.distinct_findings_found() == 1
