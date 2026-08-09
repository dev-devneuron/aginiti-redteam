"""Tests for the seven analyst-facing graph queries (aginiti/graph/
queries.py) -- the "graph as source of truth, planner as one consumer"
functions. Built entirely from hand-constructed SSGs/libraries, no live
API calls or campaign execution.
"""
from aginiti.graph.queries import (
    capabilities,
    consistent_defenses,
    disproven_assumptions,
    observed_tools,
    reachable_actions,
    recommend_next,
    security_questions,
    trust_assumptions,
    unexplored_frontier,
    unverified_capabilities,
)
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import (
    CATEGORY_MISSION_OUTCOME,
    CATEGORY_TRUST_EDGE,
    SUBGRAPH_DEFENDER,
    SUBGRAPH_TARGET,
    SecurityStateGraph,
)
from aginiti.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary, Precondition


def _op(op_id, preconditions=(), effects_success=(), effects_failure=(), cost=1, understanding_question=""):
    return Operator(
        id=op_id, description=f"do {op_id}", understanding_question=understanding_question,
        prompt="x", channel="direct", preconditions=preconditions, effects_success=effects_success,
        effects_failure=effects_failure, cost_prompts=cost, risk_tier=RiskTier.LOW,
    )


def test_trust_assumptions_returns_only_trust_edge_category_claims():
    ssg = SecurityStateGraph()
    ssg.assert_claim("trusts_slack", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    ssg.assert_claim("payroll_api_exists", "true", ClaimStatus.CONFIRMED)  # plain capability, not a trust edge

    result = trust_assumptions(ssg)

    assert [c.key for c in result] == ["trusts_slack"]


def test_disproven_assumptions_returns_only_refuted_claims():
    ssg = SecurityStateGraph()
    ssg.assert_claim("a", "true", ClaimStatus.REFUTED)
    ssg.assert_claim("b", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("c", "true", ClaimStatus.HYPOTHESIZED)

    assert [c.key for c in disproven_assumptions(ssg)] == ["a"]


def test_unverified_capabilities_returns_only_hypothesized_claims():
    ssg = SecurityStateGraph()
    ssg.assert_claim("a", "true", ClaimStatus.REFUTED)
    ssg.assert_claim("b", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("c", "true", ClaimStatus.HYPOTHESIZED)

    assert [c.key for c in unverified_capabilities(ssg)] == ["c"]


def test_consistent_defenses_requires_both_confirmed_and_defender_subgraph():
    ssg = SecurityStateGraph()
    ssg.assert_claim("blocked", "true", ClaimStatus.CONFIRMED, subgraph=SUBGRAPH_DEFENDER)
    ssg.assert_claim("hypothesized_block", "true", ClaimStatus.HYPOTHESIZED, subgraph=SUBGRAPH_DEFENDER)
    ssg.assert_claim("confirmed_but_target", "true", ClaimStatus.CONFIRMED, subgraph=SUBGRAPH_TARGET)

    assert [c.key for c in consistent_defenses(ssg)] == ["blocked"]


def test_only_latest_version_of_a_key_is_considered():
    # A claim key revised (e.g. HYPOTHESIZED -> REFUTED) must be judged by
    # its current status only, not double-counted across both versions.
    ssg = SecurityStateGraph()
    ssg.assert_claim("k", "true", ClaimStatus.HYPOTHESIZED)
    ssg.assert_claim("k", "true", ClaimStatus.REFUTED)

    assert [c.key for c in unverified_capabilities(ssg)] == []
    assert [c.key for c in disproven_assumptions(ssg)] == ["k"]


def test_unexplored_frontier_excludes_executed_and_precondition_gated_operators():
    recon = _op("recon", effects_success=(ClaimEffect("access", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),))
    reachable = _op("reachable", preconditions=(Precondition("access", ClaimStatus.HYPOTHESIZED),))
    locked = _op("locked", preconditions=(Precondition("nope", ClaimStatus.CONFIRMED),))
    ssg = SecurityStateGraph()
    ssg.assert_claim("access", "true", ClaimStatus.HYPOTHESIZED)
    library = OperatorLibrary([recon, reachable, locked])

    frontier = unexplored_frontier(ssg, library, executed_ids=frozenset({"recon"}))

    assert [op.id for op in frontier] == ["reachable"]


def test_observed_tools_dedupes_and_preserves_first_seen_order():
    ssg = SecurityStateGraph()
    ssg.record_fact("exec_1", "tool_call", {"tool": "get_current_user", "args": {}})
    ssg.record_fact("exec_1", "tool_call", {"tool": "get_user_transactions", "args": {}})
    ssg.record_fact("exec_2", "tool_call", {"tool": "get_current_user", "args": {}})  # repeat, no duplicate
    ssg.record_fact("exec_2", "response_text", {"text": "not a tool call"})  # ignored, wrong kind

    assert observed_tools(ssg) == ["get_current_user", "get_user_transactions"]


def test_observed_tools_empty_when_no_tool_call_facts_recorded():
    ssg = SecurityStateGraph()
    ssg.record_fact("exec_1", "response_text", {"text": "hello"})

    assert observed_tools(ssg) == []


def test_capabilities_defaults_untagged_claims_to_capability_category():
    ssg = SecurityStateGraph()
    ssg.assert_claim("plain_capability", "true", ClaimStatus.CONFIRMED)  # no category passed
    ssg.assert_claim("trusts_slack", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)

    assert [c.key for c in capabilities(ssg)] == ["plain_capability"]


def test_reachable_actions_requires_confirmed_and_mission_outcome_category():
    ssg = SecurityStateGraph()
    ssg.assert_claim("compromise", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME)
    ssg.assert_claim("attempted_only", "true", ClaimStatus.HYPOTHESIZED, category=CATEGORY_MISSION_OUTCOME)
    ssg.assert_claim("unrelated", "true", ClaimStatus.CONFIRMED)

    assert [c.key for c in reachable_actions(ssg)] == ["compromise"]


def test_recommend_next_ranks_and_truncates_to_n():
    a = _op("a", effects_success=(ClaimEffect("goal", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET, weight=3),))
    b = _op("b", effects_success=(ClaimEffect("side", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET, weight=1),))
    c = _op("c", effects_success=(ClaimEffect("other", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET, weight=1),))
    library = OperatorLibrary([a, b, c])
    ssg = SecurityStateGraph()
    mission = Mission(goal="test", success_criteria=("goal",), budget=10, risk_threshold=RiskTier.LOW)

    ranked = recommend_next(library, ssg, mission, prompts_used=0, n=2)

    assert len(ranked) == 2
    assert ranked[0].operator.id == "a"  # directly satisfies the mission criterion -> highest business impact


def test_recommend_next_respects_executed_ids():
    a = _op("a", effects_success=(ClaimEffect("goal", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET, weight=3),))
    library = OperatorLibrary([a])
    ssg = SecurityStateGraph()
    mission = Mission(goal="test", success_criteria=("goal",), budget=10, risk_threshold=RiskTier.LOW)

    ranked = recommend_next(library, ssg, mission, executed_ids=frozenset({"a"}))

    assert ranked == []


def test_security_questions_omits_operators_without_an_understanding_question():
    no_question = _op("no_question")  # understanding_question defaults to ""
    with_question = _op("with_question", understanding_question="Does the agent trust X?")
    library = OperatorLibrary([no_question, with_question])
    ssg = SecurityStateGraph()

    questions = security_questions(ssg, library)

    assert [q.probe_ids for q in questions] == [["with_question"]]


def test_security_questions_merges_multiple_probes_answering_the_same_question():
    # The whole point of the question-keyed inversion: two DIFFERENT
    # operators declaring the identical understanding_question should
    # merge into ONE record with both probe ids and combined evidence,
    # not two separate entries -- "questions are permanent, probes are
    # disposable."
    same_question = "Does the agent trust X?"
    probe_a = _op("probe_a", understanding_question=same_question,
                  effects_success=(ClaimEffect("trusts_x", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET),))
    probe_b = _op("probe_b", understanding_question=same_question,
                  effects_success=(ClaimEffect("trusts_x_alt", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET),))
    library = OperatorLibrary([probe_a, probe_b])
    ssg = SecurityStateGraph()
    ssg.assert_claim("trusts_x", "true", ClaimStatus.CONFIRMED)

    questions = security_questions(ssg, library, executed_ids=frozenset({"probe_a"}))

    assert len(questions) == 1
    q = questions[0]
    assert q.probe_ids == ["probe_a", "probe_b"]
    assert q.status == "answered"  # answered via probe_a even though probe_b hasn't run
    assert [c.key for c in q.claims] == ["trusts_x"]


def test_security_questions_marks_unexecuted_operator_as_unanswered():
    op = _op("probe", understanding_question="Does the agent trust X?")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()

    [q] = security_questions(ssg, library, executed_ids=frozenset())

    assert q.status == "unanswered"
    assert q.claims == []
    assert q.confidence is None


def test_security_questions_marks_hypothesized_only_result_as_partially_answered():
    op = _op("probe", understanding_question="What can the agent access?",
              effects_success=(ClaimEffect("access", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),))
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.assert_claim("access", "true", ClaimStatus.HYPOTHESIZED)

    [q] = security_questions(ssg, library, executed_ids=frozenset({"probe"}))

    assert q.status == "partially_answered"
    assert q.confidence == "low"


def test_security_questions_marks_resolved_effect_as_answered():
    op = _op("probe", understanding_question="Does the agent trust X?",
              effects_success=(ClaimEffect("trusts_x", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET),),
              effects_failure=(ClaimEffect("trusts_x", ClaimStatus.REFUTED, SUBGRAPH_TARGET),))
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.assert_claim("trusts_x", "true", ClaimStatus.REFUTED)

    [q] = security_questions(ssg, library, executed_ids=frozenset({"probe"}))

    assert q.status == "answered"
    assert [c.key for c in q.claims] == ["trusts_x"]
