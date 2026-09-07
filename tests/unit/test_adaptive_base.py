"""Tests for aginiti/adaptive/base.py -- the shared AdaptiveEngineResult
Protocol and finalize_on_success() helper (Issue #8, Tier 1)."""
from __future__ import annotations

from aginiti.adaptive.base import AdaptiveEngineResult, finalize_on_success
from aginiti.adaptive.crescendo import CrescendoResult
from aginiti.adaptive.deceptive_delight import DeceptiveDelightResult
from aginiti.adaptive.membership_inference import MembershipInferenceResult
from aginiti.adaptive.refinement import AdaptiveRefinementResult
from aginiti.adaptive.variant_discovery import VariantDiscoveryResult
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.observation_adapter import ExecutionResult
from aginiti.operators.library import ClaimEffect, Operator

_OPERATOR = Operator(
    id="test_op", description="test", prompt="prompt", channel="direct",
    preconditions=(), effects_success=(ClaimEffect("k", ClaimStatus.CONFIRMED),),
    effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
)


def _exec_result(success: bool) -> ExecutionResult:
    return ExecutionResult(
        operator_id="test_op", operator_execution_id="exec1", raw_signal="response",
        confirmed_keys=["k"] if success else [], overall_success=success,
        ground_truth_mission_achieved=False, cost_prompts=1,
        tool_trace=[], confirmed_effects=[],
    )


def test_finalize_on_success_records_final_result_on_failure_too():
    result = VariantDiscoveryResult()
    exec_result = _exec_result(success=False)

    outcome = finalize_on_success(result, _OPERATOR, exec_result)

    assert outcome is False
    assert result.final_result is exec_result
    assert result.succeeded is False
    assert result.winning_operator is None


def test_finalize_on_success_marks_succeeded_and_winning_operator_on_success():
    result = VariantDiscoveryResult()
    exec_result = _exec_result(success=True)

    outcome = finalize_on_success(result, _OPERATOR, exec_result)

    assert outcome is True
    assert result.final_result is exec_result
    assert result.succeeded is True
    assert result.winning_operator is _OPERATOR


def test_finalize_on_success_returns_the_targets_own_overall_success_value():
    # Not just truthy/falsy -- the exact bool exec_result.overall_success carries,
    # since callers use the return value directly to decide whether to stop.
    result = AdaptiveRefinementResult(operator_id="x")
    assert finalize_on_success(result, _OPERATOR, _exec_result(True)) is True
    result2 = AdaptiveRefinementResult(operator_id="x")
    assert finalize_on_success(result2, _OPERATOR, _exec_result(False)) is False


def test_every_stop_on_success_result_class_conforms_to_the_protocol():
    for cls, kwargs in [
        (VariantDiscoveryResult, {}),
        (AdaptiveRefinementResult, {"operator_id": "x"}),
        (CrescendoResult, {"goal": "x"}),
        (DeceptiveDelightResult, {"target_element": "x"}),
    ]:
        result = cls(**kwargs)
        assert isinstance(result, AdaptiveEngineResult), (
            f"{cls.__name__} does not structurally conform to AdaptiveEngineResult"
        )
        # These 4 engines have no continuous score concept -- honestly None,
        # never a fabricated 0.0/1.0 stand-in for succeeded.
        assert result.score is None
        assert result.steps_used == 0
        assert result.winning_operator is None


def test_membership_inference_result_conforms_to_the_protocol_too():
    # The one genuine outlier (no early stop, a continuous score, no single
    # "winning" probe) -- still a first-class conformer, not a footnoted
    # exception: succeeded/winning_operator are legitimately always None here.
    result = MembershipInferenceResult(candidate_doc_id="doc1")

    assert isinstance(result, AdaptiveEngineResult)
    assert result.succeeded is None
    assert result.winning_operator is None
    assert result.score == 0.0  # this engine's score IS meaningful, unlike the other 4
    assert result.steps_used == result.queries_used == 0


def test_steps_used_aliases_each_class_own_counter_without_renaming_it():
    # steps_used is additive -- the original, module-specific counter name
    # must keep working unchanged (nothing in aginiti/core/assessment.py or
    # any existing test should ever need to stop reading it).
    vd = VariantDiscoveryResult()
    assert vd.steps_used == vd.trials_used == 0

    rf = AdaptiveRefinementResult(operator_id="x")
    assert rf.steps_used == rf.attempts_used == 0

    cr = CrescendoResult(goal="x")
    assert cr.steps_used == cr.turns_used == 0

    dd = DeceptiveDelightResult(target_element="x")
    assert dd.steps_used == dd.turns_used == 0
