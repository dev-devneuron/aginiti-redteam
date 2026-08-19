"""Tests that run_campaign correctly resumes a pre-existing (e.g. reloaded
from disk) SecurityStateGraph instead of always starting fresh -- the
concrete mechanism behind "the graph outlives a single campaign." No live
API calls.
"""
from aginiti.adapter.observation_adapter import ExecutionResult
from aginiti.campaign import run_campaign
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import CATEGORY_TRUST_EDGE, SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.policies.base import Candidate


def _operator(op_id, effects_success=(), cost=1, branch=None):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct",
        preconditions=(), effects_success=effects_success,
        effects_failure=(), cost_prompts=cost, risk_tier=RiskTier.LOW, branch=branch,
    )


class _ScriptedPolicy:
    name = "scripted"

    def rank(self, library, ssg, mission, prompts_used, executed_ids):
        budget_remaining = mission.budget - prompts_used
        out = []
        for op in library:
            if op.id in executed_ids or op.cost_prompts > budget_remaining:
                continue
            if not op.preconditions_met(ssg):
                continue
            out.append(Candidate(operator=op, score=1.0))
        return out


class _FakeAdapter:
    def __init__(self, succeed: bool = True):
        self.succeed = succeed
        self.calls = 0

    def execute(self, operator, ssg, agent, seed=None):
        self.calls += 1
        effects = operator.effects_success if self.succeed else operator.effects_failure
        for effect in effects:
            ssg.assert_claim(effect.key, effect.object, effect.status, subgraph=effect.subgraph)
        return ExecutionResult(
            operator_id=operator.id, operator_execution_id=f"exec_{self.calls}",
            raw_signal="fake", confirmed_keys=[e.key for e in effects],
            overall_success=self.succeed, ground_truth_mission_achieved=False,
            cost_prompts=operator.cost_prompts,
        )


def test_run_campaign_defaults_to_a_fresh_graph_when_none_given():
    op = _operator("win", effects_success=(ClaimEffect("goal", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([op])
    mission = Mission(goal="test", success_criteria=("goal",), budget=10, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(), adapter=_FakeAdapter())

    assert result.ssg.size() >= 1
    assert result.outcome == "SUCCESS"


def test_run_campaign_skips_operators_already_executed_against_the_resumed_graph():
    # A previous session (a different process) already ran "already_run"
    # against this exact graph -- that history lives in ssg.operator_stats,
    # not in this call's local state. A resumed campaign must not re-run it.
    already_run = _operator("already_run", effects_success=(ClaimEffect("noise", ClaimStatus.CONFIRMED),))
    fresh = _operator("fresh", effects_success=(ClaimEffect("goal", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([already_run, fresh])
    mission = Mission(goal="test", success_criteria=("goal",), budget=10, risk_threshold=RiskTier.LOW)

    prior_ssg = SecurityStateGraph()
    prior_ssg.record_operator_execution("already_run", success=True)
    adapter = _FakeAdapter()

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=adapter, ssg=prior_ssg)

    # "already_run" must not be executed a second time by THIS call (its
    # prior-session execution is what operator_stats already records) --
    # only "fresh" gets a real send/judge round trip.
    assert adapter.calls == 1
    # operators_executed reports the graph's full executed set (this
    # session's new run plus what was already there), not just what this
    # particular call newly ran.
    assert set(result.operators_executed) == {"already_run", "fresh"}
    assert result.ssg is prior_ssg


def test_run_campaign_with_resumed_graph_that_already_satisfies_mission_returns_success_immediately():
    prior_ssg = SecurityStateGraph()
    prior_ssg.assert_claim("goal", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([_operator("irrelevant")])
    mission = Mission(goal="test", success_criteria=("goal",), budget=10, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=_FakeAdapter(), ssg=prior_ssg)

    assert result.outcome == "SUCCESS"
    assert result.steps_executed == 0
    assert result.operators_executed == []


# -- 2026-08-08 architecture audit: resume must backfill belief.branches ----
# from a graph's PRIOR claim history, not just claims produced from this
# call forward -- otherwise a resumed campaign's branch propagation is
# silently blind to everything a previous session already confirmed.

def test_resume_backfills_branch_beliefs_from_prior_claims_even_with_zero_new_steps():
    prior_ssg = SecurityStateGraph()
    prior_ssg.assert_claim("goal", "true", ClaimStatus.CONFIRMED)  # satisfies the mission below
    prior_ssg.assert_claim("a_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    tagged_op = _operator("probe_trust", branch="payroll",
                           effects_success=(ClaimEffect("a_trust", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    library = OperatorLibrary([tagged_op])
    mission = Mission(goal="test", success_criteria=("goal",), budget=10, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=_FakeAdapter(), ssg=prior_ssg)

    # Mission was already satisfied -- zero NEW steps ran -- yet the belief
    # state must already reflect the trust_edge claim that was already in
    # the graph before this call even started.
    assert result.steps_executed == 0
    assert "payroll" in result.ssg.belief.branches
    assert result.ssg.belief.branches["payroll"].interest > 0
    assert result.ssg.belief.cursor is not None


def test_resume_backfill_does_not_double_count_on_a_second_call():
    ssg = SecurityStateGraph()
    ssg.assert_claim("a_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    tagged_op = _operator("probe_trust", branch="payroll",
                           effects_success=(ClaimEffect("a_trust", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    library = OperatorLibrary([tagged_op])
    mission = Mission(goal="test", success_criteria=("unreachable",), budget=10, risk_threshold=RiskTier.LOW)

    run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                 adapter=_FakeAdapter(succeed=False), ssg=ssg, stop_on_mission_success=False, max_steps=0)
    first_interest = ssg.belief.branches["payroll"].interest

    # A second call on the SAME graph, cursor already set from the first --
    # must not re-backfill (re-processing "a_trust" again would double the
    # interest boost, which would be wrong -- it's the same evidence).
    run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                 adapter=_FakeAdapter(succeed=False), ssg=ssg, stop_on_mission_success=False, max_steps=0)

    assert ssg.belief.branches["payroll"].interest == first_interest
