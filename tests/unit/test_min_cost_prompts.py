"""Dynamic budgeting for reducible deep-attack operators:
`Operator.min_cost_prompts` / `effective_min_cost_prompts`, the
`satisfies_constraints` eligibility gate, and the reduced-run capping +
charging in `ObservationAdapter._execute_deep_attack`.

Fixes the "arbitrary budget lockout" of IKEA: a cost-20 IKEA operator was
hard-excluded once fewer than 20 prompts of budget remained, so the tail
budget went to a cheaper-but-less-useful operator. IKEA now stays eligible
down to `min_cost_prompts` and runs a proportionally smaller extraction,
charged for exactly what it was allocated.
"""
from __future__ import annotations

from dataclasses import replace

from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.core.observation_adapter import ObservationAdapter
from aginiti.core.policies.base import satisfies_constraints
from aginiti.operators.base import ClaimEffect, Operator


def _prompt_op(cost: int = 5, min_cost: int | None = None) -> Operator:
    return Operator(
        id="op", description="d", prompt="p", channel="direct",
        preconditions=(), effects_success=(ClaimEffect("k", ClaimStatus.CONFIRMED),),
        effects_failure=(), cost_prompts=cost, risk_tier=RiskTier.LOW,
        min_cost_prompts=min_cost,
    )


class TestEffectiveMinCostPrompts:
    def test_defaults_to_cost_prompts_when_unset(self):
        assert _prompt_op(cost=7).effective_min_cost_prompts == 7

    def test_uses_min_cost_when_set(self):
        assert _prompt_op(cost=20, min_cost=3).effective_min_cost_prompts == 3

    def test_clamped_to_cost_prompts_when_min_exceeds_cost(self):
        # A reduced run can't cost more than the full run; this keeps the
        # invariant intact if cost_prompts is lowered independently.
        assert _prompt_op(cost=1, min_cost=3).effective_min_cost_prompts == 1


class TestSatisfiesConstraints:
    def _mission(self, budget: int) -> Mission:
        return Mission(goal="g", success_criteria=("k",), budget=budget,
                       risk_threshold=RiskTier.MEDIUM, constraints=())

    def test_reducible_operator_eligible_below_full_cost(self):
        op = _prompt_op(cost=20, min_cost=3)
        # 16 remaining: full cost (20) would exclude it, min cost (3) keeps it.
        assert satisfies_constraints(op, self._mission(50), budget_remaining=16)

    def test_reducible_operator_excluded_below_its_minimum(self):
        op = _prompt_op(cost=20, min_cost=3)
        assert not satisfies_constraints(op, self._mission(50), budget_remaining=2)

    def test_non_reducible_operator_still_needs_full_cost(self):
        op = _prompt_op(cost=16)  # min_cost_prompts unset -> effective min 16
        assert not satisfies_constraints(op, self._mission(50), budget_remaining=15)
        assert satisfies_constraints(op, self._mission(50), budget_remaining=16)


class _RecordingAttack:
    """Captures the max_queries it was actually invoked with, and returns
    no findings (so the operator resolves as a non-confirmed step)."""
    last_max_queries: int | None = None

    def execute_black_box(self, **kwargs):
        type(self).last_max_queries = kwargs.get("max_queries")
        return []


class _EndpointStub:
    def close(self):
        pass


class _AgentStub:
    endpoint = _EndpointStub()

    def ground_truth_mission_achieved(self):
        return False


def _reducible_deep_attack_op(cost: int = 20, min_cost: int = 3) -> Operator:
    return Operator(
        id="deep", description="d", prompt="p", channel="direct",
        preconditions=(), effects_success=(ClaimEffect("k", ClaimStatus.CONFIRMED),),
        effects_failure=(), cost_prompts=cost, risk_tier=RiskTier.MEDIUM,
        kind="deep_attack", claim_key="k", min_cost_prompts=min_cost,
        attack_factory=lambda endpoint: _RecordingAttack(),
        attack_kwargs={"topic": "HR", "max_queries": cost},
    )


class TestReducedRunCappingAndCharging:
    def setup_method(self):
        _RecordingAttack.last_max_queries = None

    def test_full_budget_runs_full_cost_unchanged(self):
        op = _reducible_deep_attack_op(cost=20, min_cost=3)
        result = ObservationAdapter().execute(
            op, SecurityStateGraph(), _AgentStub(), budget_remaining=50)
        assert _RecordingAttack.last_max_queries == 20
        assert result.cost_prompts == 20

    def test_short_budget_caps_max_queries_and_charges_allocation(self):
        op = _reducible_deep_attack_op(cost=20, min_cost=3)
        result = ObservationAdapter().execute(
            op, SecurityStateGraph(), _AgentStub(), budget_remaining=16)
        assert _RecordingAttack.last_max_queries == 16  # capped to remaining budget
        assert result.cost_prompts == 16  # charged only what it was allocated

    def test_no_budget_hint_runs_full_cost(self):
        # Every non-campaign caller (adaptive engines, understanding loop,
        # tests) passes no budget_remaining -> full run, exactly as before.
        op = _reducible_deep_attack_op(cost=20, min_cost=3)
        result = ObservationAdapter().execute(
            op, SecurityStateGraph(), _AgentStub())
        assert _RecordingAttack.last_max_queries == 20
        assert result.cost_prompts == 20

    def test_non_reducible_operator_never_capped(self):
        # An operator without min_cost_prompts only becomes eligible at full
        # budget, so even a short budget hint must not shrink its run.
        op = replace(_reducible_deep_attack_op(cost=12), min_cost_prompts=None)
        ObservationAdapter().execute(
            op, SecurityStateGraph(), _AgentStub(), budget_remaining=5)
        assert _RecordingAttack.last_max_queries == 12
