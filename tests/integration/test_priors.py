"""Tests for aginiti/graph/priors.py's seed_target_priors -- the cold-start
fix. No live LLM calls: chat_json is mocked, same discipline as every
other judge/reasoning-layer test in this suite.
"""
from unittest.mock import patch

from aginiti.core.graph.priors import _priority_weight, _rank_positions, seed_target_priors
from aginiti.core.graph.schema import ClaimStatus, InsightCategory, RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary


def _library():
    return OperatorLibrary(data_exposure_operators())


def test_seed_target_priors_records_one_insight_per_addressed_operator():
    lib = _library()
    ssg = SecurityStateGraph()
    op_ids = [op.id for op in lib]
    verdict = {
        "priorities": {op_ids[0]: "high", op_ids[1]: "low"},
        "reasoning": {op_ids[0]: "commonly disclosed", op_ids[1]: "rarely works"},
    }
    with patch("aginiti.core.graph.priors.chat_json", return_value=verdict) as mock_chat:
        n = seed_target_priors(ssg, lib, "A RAG chat app.", seed=1)

    mock_chat.assert_called_once()
    assert n == 2
    gap_insights = [i for i in ssg.insights if i.category == InsightCategory.KNOWLEDGE_GAP]
    assert len(gap_insights) == 2
    by_probe = {i.related_probe_id: i for i in gap_insights}
    assert by_probe[op_ids[0]].importance == "high"
    assert by_probe[op_ids[1]].importance == "low"


def test_seed_target_priors_presents_candidates_in_a_stable_id_sorted_order():
    # 2026-08-09 fix: live-diagnosed real bug -- the SAME candidate set,
    # presented in two different (per-trial-shuffled) library orders, got
    # WILDLY different LLM verdicts for the identical operator (a known
    # trap rated "low" in one order, "high" in another) -- classic LLM
    # listwise position bias. The fix decouples the prompt's candidate
    # order from library's own iteration order entirely: this locks in
    # that the `user` message chat_json receives always lists candidates
    # sorted by op.id, regardless of what order `library` iterates in.
    import json

    ops = list(data_exposure_operators())
    reversed_lib = OperatorLibrary(list(reversed(ops)))
    forward_lib = OperatorLibrary(ops)
    expected_order = [op.id for op in sorted(ops, key=lambda o: o.id)]

    captured = {}

    def _capture(messages, **kwargs):
        captured["user"] = messages[1]["content"]
        return {"priorities": {}, "rank": [], "reasoning": {}}

    with patch("aginiti.core.graph.priors.chat_json", side_effect=_capture):
        seed_target_priors(SecurityStateGraph(), reversed_lib, "ctx", seed=1)
    reversed_call_order = [c["id"] for c in json.loads(captured["user"].split("Candidate probes:\n", 1)[1])]

    with patch("aginiti.core.graph.priors.chat_json", side_effect=_capture):
        seed_target_priors(SecurityStateGraph(), forward_lib, "ctx", seed=1)
    forward_call_order = [c["id"] for c in json.loads(captured["user"].split("Candidate probes:\n", 1)[1])]

    assert reversed_call_order == forward_call_order == expected_order


def test_seeded_priors_are_actually_readable_by_gap_priority():
    # The whole point: AginitiPlanner.gap_priority() must pick these up
    # completely unchanged -- no planner code touched.
    from aginiti.core.planner.aginiti_planner import AginitiPlanner

    lib = _library()
    ssg = SecurityStateGraph()
    target_op = next(iter(lib)).id
    verdict = {"priorities": {target_op: "high"}, "reasoning": {}}
    with patch("aginiti.core.graph.priors.chat_json", return_value=verdict):
        seed_target_priors(ssg, lib, "context", seed=1)

    planner = AginitiPlanner()
    op = lib.get(target_op)
    assert planner.gap_priority(op, ssg) == 4.0  # IMPORTANCE_WEIGHT["high"]


def test_hallucinated_operator_id_is_silently_skipped_not_recorded():
    lib = _library()
    ssg = SecurityStateGraph()
    verdict = {"priorities": {"not_a_real_operator_id": "high"}, "reasoning": {}}
    with patch("aginiti.core.graph.priors.chat_json", return_value=verdict):
        n = seed_target_priors(ssg, lib, "context", seed=1)

    assert n == 0
    assert ssg.insights == []


def test_malformed_importance_level_is_silently_skipped_not_recorded():
    lib = _library()
    ssg = SecurityStateGraph()
    op_id = next(iter(lib)).id
    verdict = {"priorities": {op_id: "extremely-high"}, "reasoning": {}}  # not low/medium/high
    with patch("aginiti.core.graph.priors.chat_json", return_value=verdict):
        n = seed_target_priors(ssg, lib, "context", seed=1)

    assert n == 0


def test_malformed_priorities_shape_returns_zero_not_a_crash():
    lib = _library()
    ssg = SecurityStateGraph()
    with patch("aginiti.core.graph.priors.chat_json", return_value={"priorities": "not-a-dict"}):
        n = seed_target_priors(ssg, lib, "context", seed=1)
    assert n == 0
    assert ssg.insights == []


def test_empty_library_never_calls_the_llm_at_all():
    ssg = SecurityStateGraph()
    with patch("aginiti.core.graph.priors.chat_json") as mock_chat:
        n = seed_target_priors(ssg, OperatorLibrary([]), "context", seed=1)
    mock_chat.assert_not_called()
    assert n == 0


def test_seed_target_priors_warns_and_returns_zero_on_a_parse_error():
    # 2026-08-09 fix: a truncated/malformed chat_json response for THIS
    # call used to silently produce priorities={} (the "priorities" key is
    # simply absent from the {"_parse_error": True, "_raw": ...} fallback,
    # so .get("priorities", {}) defaults to empty) -- recording ZERO
    # priors with no visible sign anything went wrong. Must now warn.
    import warnings

    lib = _library()
    ssg = SecurityStateGraph()
    with patch("aginiti.core.graph.priors.chat_json",
               return_value={"_parse_error": True, "_raw": '{"priorities": {"a": "hi'}):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            n = seed_target_priors(ssg, lib, "context", seed=1)

    assert n == 0
    assert any("parse" in str(w.message).lower() for w in caught)


def test_seed_target_priors_max_tokens_scales_with_library_size():
    # A larger library needs more response headroom -- this locks in that
    # the token budget actually grows with candidate count instead of
    # staying at chat_json's flat 400-token default regardless of how many
    # operators are being asked about. Uses a synthetic 15-operator
    # library (real ones here are only 6 -- too small to clear the 600-
    # token floor and actually demonstrate scaling) to exceed the floor.
    def _synthetic_op(i):
        return Operator(
            id=f"synthetic_{i}", description=f"synthetic op {i}", prompt="x", channel="direct",
            preconditions=(), effects_success=(ClaimEffect(f"key_{i}", ClaimStatus.CONFIRMED),),
            effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
        )

    small_lib = OperatorLibrary(list(data_exposure_operators())[:2])
    big_lib = OperatorLibrary([_synthetic_op(i) for i in range(15)])
    assert len(big_lib) > len(small_lib)

    calls = {}

    def _capture(messages, max_tokens=None, seed=None):
        calls["max_tokens"] = max_tokens
        return {"priorities": {}, "rank": [], "reasoning": {}}

    with patch("aginiti.core.graph.priors.chat_json", side_effect=_capture):
        seed_target_priors(SecurityStateGraph(), small_lib, "context", seed=1)
    small_tokens = calls["max_tokens"]

    with patch("aginiti.core.graph.priors.chat_json", side_effect=_capture):
        seed_target_priors(SecurityStateGraph(), big_lib, "context", seed=1)
    big_tokens = calls["max_tokens"]

    assert big_tokens > small_tokens


# -- run_campaign wiring ------------------------------------------------

class _FakeAdapter:
    """Same fake used throughout tests/integration/test_campaign.py -- bypasses the
    real ObservationAdapter (and therefore any judge/target LLM call)
    entirely, so this test only ever exercises priors.py's own call."""

    def __init__(self):
        self.calls = 0

    def execute(self, operator, ssg, agent, seed=None):
        from aginiti.core.observation_adapter import ExecutionResult
        self.calls += 1
        return ExecutionResult(
            operator_id=operator.id, operator_execution_id=f"exec_{self.calls}",
            raw_signal="fake", confirmed_keys=[], overall_success=False,
            ground_truth_mission_achieved=False, cost_prompts=operator.cost_prompts,
        )


def test_run_campaign_does_not_seed_priors_by_default():
    from aginiti.core.campaign import run_campaign
    from aginiti.core.graph.schema import RiskTier
    from aginiti.core.mission import Mission
    from aginiti.core.policies.random_policy import RandomPolicy

    lib = _library()
    mission = Mission(goal="x", success_criteria=("system_prompt_disclosed",),
                       success_mode="any", budget=1, risk_threshold=RiskTier.MEDIUM)
    with patch("aginiti.core.graph.priors.chat_json") as mock_priors_chat:
        run_campaign(mission, lib, agent=object(), policy=RandomPolicy(seed=1),
                     adapter=_FakeAdapter(), max_steps=1, seed=1)
    mock_priors_chat.assert_not_called()


def test_run_campaign_seeds_priors_when_target_briefing_given():
    from aginiti.core.campaign import run_campaign
    from aginiti.core.graph.schema import RiskTier
    from aginiti.core.mission import Mission
    from aginiti.core.policies.random_policy import RandomPolicy

    lib = _library()
    mission = Mission(goal="x", success_criteria=("system_prompt_disclosed",),
                       success_mode="any", budget=1, risk_threshold=RiskTier.MEDIUM)
    verdict = {"priorities": {}, "reasoning": {}}
    with patch("aginiti.core.graph.priors.chat_json", return_value=verdict) as mock_priors_chat:
        run_campaign(mission, lib, agent=object(), policy=RandomPolicy(seed=1),
                     adapter=_FakeAdapter(), max_steps=1, seed=1, target_briefing="A RAG chat app.")
    mock_priors_chat.assert_called_once()


def test_run_campaign_does_not_reseed_priors_on_a_graph_that_already_has_a_knowledge_gap():
    # 2026-08-09 idempotency fix: a persistent graph reused across sessions
    # (aginiti/graph/persistence.py's whole point) should only ever pay for
    # this LLM call once per graph, not once per resumed campaign.
    from aginiti.core.campaign import run_campaign
    from aginiti.core.graph.schema import RiskTier
    from aginiti.core.mission import Mission
    from aginiti.core.policies.random_policy import RandomPolicy

    lib = _library()
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "already seeded", importance="high",
                        related_probe_id=next(iter(lib)).id)
    mission = Mission(goal="x", success_criteria=("system_prompt_disclosed",),
                       success_mode="any", budget=1, risk_threshold=RiskTier.MEDIUM)
    with patch("aginiti.core.graph.priors.chat_json") as mock_priors_chat:
        run_campaign(mission, lib, agent=object(), policy=RandomPolicy(seed=1),
                     adapter=_FakeAdapter(), max_steps=1, seed=1, target_briefing="A RAG chat app.",
                     ssg=ssg)
    mock_priors_chat.assert_not_called()


# -- rank-based priority_weight nudge (2026-08-09 tie-breaking fix) --------

def test_rank_positions_parses_a_well_formed_list():
    assert _rank_positions(["b", "a", "c"], {"a", "b", "c"}) == {"b": 0, "a": 1, "c": 2}


def test_rank_positions_drops_hallucinated_ids_not_in_valid_set():
    assert _rank_positions(["a", "ghost", "b"], {"a", "b"}) == {"a": 0, "b": 1}


def test_rank_positions_keeps_only_the_first_occurrence_of_a_duplicate():
    assert _rank_positions(["a", "b", "a"], {"a", "b"}) == {"a": 0, "b": 1}


def test_rank_positions_returns_empty_dict_for_a_non_list_value():
    assert _rank_positions("not-a-list", {"a", "b"}) == {}
    assert _rank_positions(None, {"a", "b"}) == {}


def test_priority_weight_no_rank_info_returns_bare_bucket_weight():
    assert _priority_weight("medium", rank_index=None, n_ranked=0) == 2.0
    assert _priority_weight("high", rank_index=None, n_ranked=0) == 4.0


def test_priority_weight_most_promising_gets_upper_end_of_the_bucket():
    # rank_index=0 out of 3 ranked -> most promising -> base + 0.2
    assert _priority_weight("medium", rank_index=0, n_ranked=3) == 2.2


def test_priority_weight_least_promising_gets_lower_end_of_the_bucket():
    assert _priority_weight("medium", rank_index=2, n_ranked=3) == 1.8


def test_priority_weight_never_crosses_into_a_neighboring_bucket():
    # Worst-case nudge in either direction must never let "low" beat
    # "medium" or "medium" beat "high" purely from rank position.
    low_best_case = _priority_weight("low", rank_index=0, n_ranked=2)
    medium_worst_case = _priority_weight("medium", rank_index=1, n_ranked=2)
    high_worst_case = _priority_weight("high", rank_index=1, n_ranked=2)
    assert low_best_case < medium_worst_case < high_worst_case


def test_seed_target_priors_breaks_a_same_bucket_tie_using_rank():
    # The exact real-world scenario this fix closes: two operators rated
    # the identical bucket ("medium") must not end up with identical
    # gap_priority once a rank ordering is available to break the tie.
    lib = _library()
    op_ids = [op.id for op in lib]
    trap_id, real_win_id = op_ids[0], op_ids[1]
    verdict = {
        "priorities": {trap_id: "medium", real_win_id: "medium"},
        "rank": [real_win_id, trap_id],  # real_win ranked more promising than trap
        "reasoning": {},
    }
    ssg = SecurityStateGraph()
    with patch("aginiti.core.graph.priors.chat_json", return_value=verdict):
        seed_target_priors(ssg, lib, "context", seed=1)

    by_probe = {i.related_probe_id: i for i in ssg.insights if i.category == InsightCategory.KNOWLEDGE_GAP}
    assert by_probe[trap_id].importance == by_probe[real_win_id].importance == "medium"  # same bucket
    assert by_probe[real_win_id].priority_weight > by_probe[trap_id].priority_weight  # no longer tied


def test_seed_target_priors_degrades_gracefully_when_rank_is_missing():
    # No `rank` key at all (an older-shaped or malformed response) ->
    # priority_weight falls back to the bare bucket weight, same as before
    # this fix existed -- not a crash, not a fabricated ordering.
    lib = _library()
    op_id = next(iter(lib)).id
    verdict = {"priorities": {op_id: "high"}, "reasoning": {}}  # no "rank" key
    ssg = SecurityStateGraph()
    with patch("aginiti.core.graph.priors.chat_json", return_value=verdict):
        seed_target_priors(ssg, lib, "context", seed=1)

    insight = next(i for i in ssg.insights if i.related_probe_id == op_id)
    assert insight.priority_weight == 4.0  # bare "high" bucket weight, no nudge
