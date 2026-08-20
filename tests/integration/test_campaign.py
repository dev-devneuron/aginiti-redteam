"""Tests the campaign loop's termination logic (SUCCESS / BUDGET_EXHAUSTED /
SEARCH_EXHAUSTED) with fake policy/adapter doubles -- no live API calls.
Complements test_operators.py and test_llm_client.py, which cover the
pieces the loop calls out to; this covers the loop's own control flow.
"""
from aginiti.core.observation_adapter import ExecutionResult
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary, Precondition
from aginiti.core.policies.base import Candidate


def _operator(op_id, effects_success=(), effects_failure=(), preconditions=(), cost=1):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct",
        preconditions=preconditions, effects_success=effects_success,
        effects_failure=effects_failure, cost_prompts=cost, risk_tier=RiskTier.LOW,
    )


class _ScriptedPolicy:
    """Ranks whatever's still eligible in library-declaration order, exactly
    once per operator (mirrors AginitiPlanner's one-shot-per-operator rule)."""
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


class _UnlimitedRetryPolicy:
    """Always re-offers the same operator, ignoring executed_ids -- used to
    exercise the max_steps cap directly."""
    name = "unlimited_retry"

    def __init__(self, operator):
        self.operator = operator

    def rank(self, library, ssg, mission, prompts_used, executed_ids):
        budget_remaining = mission.budget - prompts_used
        if self.operator.cost_prompts > budget_remaining:
            return []
        return [Candidate(operator=self.operator, score=1.0)]


class _FakeAdapter:
    """Applies an operator's declared success (or failure) effects directly
    to the SSG, standing in for a real target + judge round trip."""

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


def test_campaign_succeeds_when_adapter_confirms_mission_criterion():
    op = _operator("win", effects_success=(ClaimEffect("goal_achieved", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([op])
    mission = Mission(goal="test", success_criteria=("goal_achieved",), budget=10, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=_FakeAdapter(succeed=True))

    assert result.outcome == "SUCCESS"
    assert result.operators_executed == ["win"]


def test_campaign_search_exhausted_when_operators_run_out_without_success():
    op = _operator("dead_end", effects_success=(ClaimEffect("goal_achieved", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([op])
    mission = Mission(goal="test", success_criteria=("goal_achieved",), budget=10, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=_FakeAdapter(succeed=False))

    assert result.outcome == "SEARCH_EXHAUSTED"
    assert result.operators_executed == ["dead_end"]  # ran once, then no candidates left


def test_campaign_budget_exhausted_when_operator_too_expensive():
    op = _operator("expensive", cost=5, effects_success=(ClaimEffect("goal_achieved", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([op])
    mission = Mission(goal="test", success_criteria=("goal_achieved",), budget=2, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=_FakeAdapter(succeed=True))

    assert result.outcome == "BUDGET_EXHAUSTED"
    assert result.operators_executed == []


def test_campaign_stops_at_max_steps_even_if_policy_never_gives_up():
    op = _operator("loop_forever", cost=1, effects_success=())  # never satisfies any mission criterion
    library = OperatorLibrary([op])
    mission = Mission(goal="test", success_criteria=("unreachable",), budget=100, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_UnlimitedRetryPolicy(op),
                           adapter=_FakeAdapter(succeed=True), max_steps=5)

    assert result.outcome == "BUDGET_EXHAUSTED"
    assert result.steps_executed == 5
    assert len(result.operators_executed) == 5


def test_campaign_with_stop_on_mission_success_false_keeps_probing_past_a_win():
    # "win" satisfies the mission but there's a second, unrelated operator
    # still eligible -- understanding-mode should keep running to collect
    # it instead of stopping the instant the mission is satisfied.
    win = _operator("win", effects_success=(ClaimEffect("goal_achieved", ClaimStatus.CONFIRMED),))
    also_probe = _operator("also_probe", effects_success=(ClaimEffect("side_fact", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([win, also_probe])
    mission = Mission(goal="test", success_criteria=("goal_achieved",), budget=10, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=_FakeAdapter(succeed=True), stop_on_mission_success=False)

    # Both operators ran (the mission being satisfied after "win" didn't
    # stop the loop), and the outcome still correctly reads SUCCESS off
    # the final graph state.
    assert set(result.operators_executed) == {"win", "also_probe"}
    assert result.outcome == "SUCCESS"


def test_campaign_stop_on_mission_success_true_still_stops_immediately_by_default():
    # Regression test: the default must reproduce the original behavior
    # exactly, since the frozen RQ1 benchmark's efficiency metric depends
    # on it -- a second eligible operator must NOT run.
    win = _operator("win", effects_success=(ClaimEffect("goal_achieved", ClaimStatus.CONFIRMED),))
    also_probe = _operator("also_probe", effects_success=(ClaimEffect("side_fact", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([win, also_probe])
    mission = Mission(goal="test", success_criteria=("goal_achieved",), budget=10, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=_FakeAdapter(succeed=True))

    assert result.operators_executed == ["win"]
    assert result.outcome == "SUCCESS"


def test_campaign_reports_success_when_final_step_at_max_steps_satisfies_mission():
    # Edge case fix: previously, if mission satisfaction happened to land
    # exactly on the max_steps-th action, the loop exited via the max_steps
    # bound (never re-checking mission.is_satisfied) and misreported
    # BUDGET_EXHAUSTED even though the graph shows the mission was met.
    win = _operator("win", effects_success=(ClaimEffect("goal_achieved", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([win])
    mission = Mission(goal="test", success_criteria=("goal_achieved",), budget=10, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=_FakeAdapter(succeed=True), stop_on_mission_success=False, max_steps=1)

    assert result.steps_executed == 1
    assert result.outcome == "SUCCESS"


def test_campaign_respects_preconditions_via_scripted_policy():
    gate = _operator("gate", effects_success=(ClaimEffect("unlocked", ClaimStatus.CONFIRMED),))
    locked = _operator("locked_op", preconditions=(Precondition("unlocked", ClaimStatus.CONFIRMED),),
                        effects_success=(ClaimEffect("goal_achieved", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([gate, locked])
    mission = Mission(goal="test", success_criteria=("goal_achieved",), budget=10, risk_threshold=RiskTier.LOW)

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=_FakeAdapter(succeed=True))

    assert result.outcome == "SUCCESS"
    assert result.operators_executed == ["gate", "locked_op"]


def test_campaign_logs_start_and_finish(caplog):
    # 2026-08-09 production-readiness addition: a deploying application
    # attaching its own handler to the "aginiti" logger must see a real
    # start/finish record for every campaign, not just print() output only
    # a human at a terminal would ever see.
    import logging
    win = _operator("win", effects_success=(ClaimEffect("goal_achieved", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([win])
    mission = Mission(goal="test", success_criteria=("goal_achieved",), budget=10, risk_threshold=RiskTier.LOW)

    with caplog.at_level(logging.INFO, logger="aginiti.campaign"):
        result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                               adapter=_FakeAdapter(succeed=True))

    assert result.outcome == "SUCCESS"
    assert "campaign starting" in caplog.text
    assert "campaign finished" in caplog.text and "outcome=SUCCESS" in caplog.text
