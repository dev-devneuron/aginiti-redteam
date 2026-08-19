"""Tests for run_understanding_loop (aginiti/understanding_loop.py) -- the
Plan -> Execute -> Learn -> Repeat loop. No live API calls: both the judge
(via a fake ObservationAdapter) and insight synthesis (via a patched
synthesize_insights) are stubbed, same pattern as test_campaign.py and
test_insights.py.
"""
from unittest.mock import patch

from aginiti.adapter.observation_adapter import ExecutionResult
from aginiti.graph.schema import ClaimStatus, InsightCategory, RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.understanding_loop import run_understanding_loop


def _op(op_id, effects_success=(), cost=1):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=effects_success, effects_failure=(), cost_prompts=cost, risk_tier=RiskTier.LOW,
    )


def _mission():
    return Mission(goal="test", success_criteria=("unreachable",), budget=20, risk_threshold=RiskTier.LOW)


class _FakeAdapter:
    """Applies an operator's success effects directly to the SSG, standing
    in for a real target + judge round trip -- same pattern as
    test_campaign.py's _FakeAdapter."""

    def __init__(self):
        self.calls = 0

    def execute(self, operator, ssg, agent, seed=None):
        self.calls += 1
        for effect in operator.effects_success:
            ssg.assert_claim(effect.key, effect.object, effect.status, subgraph=effect.subgraph,
                              category=effect.category)
        return ExecutionResult(
            operator_id=operator.id, operator_execution_id=f"exec_{self.calls}",
            raw_signal="fake", confirmed_keys=[e.key for e in operator.effects_success],
            overall_success=True, ground_truth_mission_achieved=False, cost_prompts=operator.cost_prompts,
        )


def test_loop_stops_when_no_eligible_operator_remains():
    op = _op("probe", effects_success=(ClaimEffect("k", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([op])

    with patch("aginiti.understanding_loop.synthesize_insights", return_value=[]):
        result = run_understanding_loop(_mission(), library, agent=object(), target_name="test-target",
                                         adapter=_FakeAdapter())

    assert len(result.rounds) == 1  # only one operator, ran once, then nothing left
    assert result.rounds[0].chosen_operator_id == "probe"


def test_loop_respects_max_rounds():
    # An operator whose effect never resolves the underlying claim to
    # something that removes it from eligibility -- but each round is a
    # DIFFERENT operator here so max_rounds is the only thing capping it.
    ops = [_op(f"probe_{i}", effects_success=(ClaimEffect(f"k{i}", ClaimStatus.CONFIRMED),)) for i in range(5)]
    library = OperatorLibrary(ops)

    with patch("aginiti.understanding_loop.synthesize_insights", return_value=[]):
        result = run_understanding_loop(_mission(), library, agent=object(), target_name="test-target",
                                         adapter=_FakeAdapter(), max_rounds=3)

    assert len(result.rounds) == 3


def test_loop_calls_synthesize_insights_after_every_round_not_just_once():
    op_a = _op("probe_a", effects_success=(ClaimEffect("ka", ClaimStatus.CONFIRMED),))
    op_b = _op("probe_b", effects_success=(ClaimEffect("kb", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([op_a, op_b])

    with patch("aginiti.understanding_loop.synthesize_insights", return_value=[]) as mock_synth:
        run_understanding_loop(_mission(), library, agent=object(), target_name="test-target",
                                adapter=_FakeAdapter())

    assert mock_synth.call_count == 2  # once per round, not once at the end


def test_loop_records_new_insights_per_round():
    op = _op("probe", effects_success=(ClaimEffect("k", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    fake_insight = ssg.record_insight(InsightCategory.BEHAVIORAL, "placeholder", derived_from=("k",))

    with patch("aginiti.understanding_loop.synthesize_insights", return_value=[fake_insight]):
        result = run_understanding_loop(_mission(), library, agent=object(), target_name="test-target",
                                         ssg=SecurityStateGraph(), adapter=_FakeAdapter())

    assert result.rounds[0].new_insights == [fake_insight]


def test_a_knowledge_gap_from_round_one_changes_round_two_selection():
    # The concrete claim: a gap synthesized after round 1, naming probe_b
    # as its related probe, should make probe_b win round 2 over an
    # otherwise-equal-utility probe_c -- the planner reading back what
    # synthesis just produced, not just narrative.
    probe_a = _op("probe_a", effects_success=(ClaimEffect("ka", ClaimStatus.CONFIRMED),))
    probe_b = _op("probe_b", effects_success=(ClaimEffect("kb", ClaimStatus.CONFIRMED),))
    probe_c = _op("probe_c", effects_success=(ClaimEffect("kc", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([probe_a, probe_b, probe_c])

    call_count = {"n": 0}

    def fake_synthesize(ssg, target_name, library=None, executed_ids=frozenset(), seed=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # After round 1 (probe_a ran, alphabetically/insertion-order
            # first with equal utility to b and c), synthesize a gap
            # pointing at probe_b specifically.
            return [ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "gap favoring b",
                                        importance="high", related_probe_id="probe_b")]
        return []

    with patch("aginiti.understanding_loop.synthesize_insights", side_effect=fake_synthesize):
        result = run_understanding_loop(_mission(), library, agent=object(), target_name="test-target",
                                         adapter=_FakeAdapter(), max_rounds=2)

    assert result.rounds[0].chosen_operator_id == "probe_a"
    assert result.rounds[1].chosen_operator_id == "probe_b"  # pulled ahead of probe_c by the new gap
