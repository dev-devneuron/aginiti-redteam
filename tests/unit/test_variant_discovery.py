from aginiti.core.observation_adapter import _effect_id
from aginiti.adapters.base import SendResult
from aginiti.adaptive.variant_discovery import run_variant_discovery
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.operators.library import ClaimEffect, Operator


def _make_variant_operator(variant_id: str, always_succeeds: bool):
    effect = ClaimEffect(f"{variant_id}_claim", ClaimStatus.CONFIRMED)
    return Operator(
        id=variant_id, description="test variant", prompt=f"prompt for {variant_id}", channel="direct",
        preconditions=(), effects_success=(effect,), effects_failure=(),
        cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw_signal: [_effect_id(effect)] if always_succeeds else [],
    )


class _CountingAdapter:
    def __init__(self):
        self.calls = 0

    def send(self, channel, prompt):
        self.calls += 1
        return SendResult(final_text="response")

    def ground_truth_mission_achieved(self):
        return False


def test_stops_on_first_candidate_that_succeeds():
    variants = [_make_variant_operator("v1", False), _make_variant_operator("v2", True),
                _make_variant_operator("v3", True)]

    def next_fn(history):
        return (variants[len(history)], variants[len(history)].id) if len(history) < len(variants) else None

    ssg = SecurityStateGraph()
    adapter = _CountingAdapter()
    result = run_variant_discovery(next_fn, ssg, adapter, max_trials=10)

    assert result.succeeded is True
    assert result.trials_used == 2  # v1 fails, v2 succeeds -- never reaches v3
    assert result.winning_operator.id == "v2"
    assert adapter.calls == 2


def test_exhausts_all_candidates_when_none_succeed():
    variants = [_make_variant_operator(f"v{i}", False) for i in range(4)]

    def next_fn(history):
        return (variants[len(history)], variants[len(history)].id) if len(history) < len(variants) else None

    ssg = SecurityStateGraph()
    result = run_variant_discovery(next_fn, ssg, _CountingAdapter(), max_trials=10)

    assert result.succeeded is False
    assert result.trials_used == 4
    assert result.winning_operator is None


def test_respects_max_trials_even_if_more_candidates_are_available():
    variants = [_make_variant_operator(f"v{i}", False) for i in range(10)]

    def next_fn(history):
        return (variants[len(history)], variants[len(history)].id) if len(history) < len(variants) else None

    ssg = SecurityStateGraph()
    result = run_variant_discovery(next_fn, ssg, _CountingAdapter(), max_trials=3)

    assert result.trials_used == 3
    assert result.succeeded is False


def test_candidate_fn_returning_none_immediately_stops_with_zero_trials():
    ssg = SecurityStateGraph()
    result = run_variant_discovery(lambda history: None, ssg, _CountingAdapter(), max_trials=5)

    assert result.trials_used == 0
    assert result.succeeded is False
    assert result.winning_operator is None


def test_full_trial_trace_is_recorded_including_failures_before_success():
    variants = [_make_variant_operator("v1", False), _make_variant_operator("v2", False),
                _make_variant_operator("v3", True)]

    def next_fn(history):
        return (variants[len(history)], variants[len(history)].id) if len(history) < len(variants) else None

    ssg = SecurityStateGraph()
    result = run_variant_discovery(next_fn, ssg, _CountingAdapter(), max_trials=10)

    assert [t.variant_name for t in result.trials] == ["v1", "v2", "v3"]
    assert [t.success for t in result.trials] == [False, False, True]
    assert [t.trial_number for t in result.trials] == [1, 2, 3]


def test_candidate_fn_receives_the_history_so_far_each_call():
    seen_history_lengths = []

    def next_fn(history):
        seen_history_lengths.append(len(history))
        if len(history) >= 3:
            return None
        return _make_variant_operator(f"v{len(history)}", False), f"v{len(history)}"

    ssg = SecurityStateGraph()
    run_variant_discovery(next_fn, ssg, _CountingAdapter(), max_trials=10)

    assert seen_history_lengths == [0, 1, 2, 3]
