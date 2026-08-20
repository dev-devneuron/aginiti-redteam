"""Tests for the Insight tier (schema.py's fourth tier above Fact/
Observation/Claim) and its synthesis (aginiti/graph/insights.py) into
three categories: behavioral, security, knowledge_gap. The LLM call is
mocked throughout -- no live API usage -- consistent with how
test_observation_adapter.py handles the judge call.
"""
from unittest.mock import patch

from aginiti.core.graph.hypothesis import HypothesisStatus
from aginiti.core.graph.insights import synthesize_insights
from aginiti.core.graph.schema import ClaimStatus, InsightCategory
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary, Precondition


def _op(op_id, description="", understanding_question="", effects_success=(), preconditions=()):
    from aginiti.core.graph.schema import RiskTier
    return Operator(
        id=op_id, description=description, understanding_question=understanding_question,
        prompt="x", channel="direct", preconditions=preconditions, effects_success=effects_success,
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )


def test_record_insight_appends_and_returns_it():
    ssg = SecurityStateGraph()
    insight = ssg.record_insight(InsightCategory.BEHAVIORAL, "the agent trusts X", derived_from=("k1", "k2"))

    assert ssg.insights == [insight]
    assert insight.category == InsightCategory.BEHAVIORAL
    assert insight.statement == "the agent trusts X"
    assert insight.derived_from == ("k1", "k2")
    assert insight.related_probe_id is None


def test_record_insight_supports_knowledge_gap_with_related_probe():
    ssg = SecurityStateGraph()
    insight = ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "memory persistence unknown",
                                  related_probe_id="probe_memory")

    assert insight.category == InsightCategory.KNOWLEDGE_GAP
    assert insight.derived_from == ()
    assert insight.related_probe_id == "probe_memory"


def test_synthesize_insights_skips_the_llm_call_when_nothing_is_resolved():
    ssg = SecurityStateGraph()
    ssg.assert_claim("maybe", "true", ClaimStatus.HYPOTHESIZED)

    with patch("aginiti.core.graph.insights.chat_json") as mock_chat:
        result = synthesize_insights(ssg, target_name="test-target")

    mock_chat.assert_not_called()
    assert result == []


def test_synthesize_insights_records_grounded_behavioral_and_security_only():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("k2", "true", ClaimStatus.CONFIRMED)

    fake_verdict = {
        "behavioral_insights": [
            {"statement": "grounded behavioral finding", "claim_keys": ["k1", "k2"]},
            {"statement": "ungrounded finding", "claim_keys": ["not_a_real_key"]},  # dropped
            {"statement": "", "claim_keys": ["k1"]},  # empty statement, dropped
        ],
        "security_insights": [
            {"statement": "grounded security finding", "claim_keys": ["k1"]},
        ],
        "knowledge_gaps": [],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        result = synthesize_insights(ssg, target_name="test-target")

    behavioral = [r for r in result if r.category == InsightCategory.BEHAVIORAL]
    security = [r for r in result if r.category == InsightCategory.SECURITY]
    assert len(behavioral) == 1
    assert behavioral[0].statement == "grounded behavioral finding"
    assert behavioral[0].derived_from == ("k1", "k2")
    assert len(security) == 1
    assert security[0].derived_from == ("k1",)
    assert ssg.insights == result  # actually recorded on the graph, not just returned


def test_synthesize_insights_captures_confidence_alternatives_and_missing_evidence():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)

    fake_verdict = {
        "behavioral_insights": [{
            "statement": "the agent inspects tool arguments before execution",
            "claim_keys": ["k1"],
            "confidence": "Medium",  # case-insensitive
            "alternative_explanations": ["model-level safety", "wrapper validation", ""],  # blank dropped
            "evidence_still_missing": ["  only one user role tested  ", "no delegated authority tested", ""],
        }],
        "security_insights": [], "knowledge_gaps": [],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        result = synthesize_insights(ssg, target_name="test-target")

    ins = result[0]
    assert ins.confidence == "medium"
    assert ins.alternative_explanations == ("model-level safety", "wrapper validation")
    assert ins.evidence_still_missing == ("only one user role tested", "no delegated authority tested")


def test_synthesize_insights_evidence_still_missing_ignores_non_list_value():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)

    fake_verdict = {
        "behavioral_insights": [{"statement": "x", "claim_keys": ["k1"], "evidence_still_missing": "not a list"}],
        "security_insights": [], "knowledge_gaps": [],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        result = synthesize_insights(ssg, target_name="test-target")

    assert result[0].evidence_still_missing == ()


def test_synthesize_insights_drops_invalid_confidence_level():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)

    fake_verdict = {
        "behavioral_insights": [{"statement": "x", "claim_keys": ["k1"], "confidence": "extremely sure"}],
        "security_insights": [], "knowledge_gaps": [],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        result = synthesize_insights(ssg, target_name="test-target")

    assert result[0].confidence is None  # not a recognized low/medium/high level


def test_synthesize_insights_captures_gap_importance():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)

    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{"topic": "memory", "why_it_matters": "unknown", "importance": "high"}],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        result = synthesize_insights(ssg, target_name="test-target")

    assert result[0].importance == "high"


def test_synthesize_insights_captures_gap_prior_belief_and_confidence():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)

    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{
            "topic": "memory persistence", "why_it_matters": "unknown", "importance": "high",
            "prior_belief": "probably persists memory, given the framework's typical checkpointing",
            "prior_confidence": "low",
        }],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        result = synthesize_insights(ssg, target_name="test-target")

    gap = result[0]
    assert gap.prior_belief == "probably persists memory, given the framework's typical checkpointing"
    assert gap.confidence == "low"  # prior_confidence reuses the `confidence` field for gaps


def test_synthesize_insights_gap_without_prior_belief_leaves_it_none():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)

    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{"topic": "memory persistence", "why_it_matters": "unknown", "importance": "high"}],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        result = synthesize_insights(ssg, target_name="test-target")

    assert result[0].prior_belief is None


def test_synthesize_insights_links_knowledge_gap_to_a_matching_unexplored_probe():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([
        _op("probe_memory", description="Ask whether the agent remembers prior turns",
            understanding_question="Does the agent persist memory across turns?"),
        _op("probe_unrelated", description="Ask about lunch preferences",
            understanding_question="Does the agent have an opinion on lunch?"),
    ])
    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{"topic": "memory persistence", "why_it_matters": "unknown if turns persist"}],
    }

    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        result = synthesize_insights(ssg, target_name="test-target", library=library)

    assert len(result) == 1
    gap = result[0]
    assert gap.category == InsightCategory.KNOWLEDGE_GAP
    assert gap.related_probe_id == "probe_memory"


def test_synthesize_insights_leaves_related_probe_none_when_nothing_matches():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([
        _op("probe_unrelated", description="Ask about lunch preferences",
            understanding_question="Does the agent have an opinion on lunch?"),
    ])
    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{"topic": "quantum cryptography", "why_it_matters": "totally unrelated topic"}],
    }

    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        result = synthesize_insights(ssg, target_name="test-target", library=library)

    assert result[0].related_probe_id is None


def test_synthesize_insights_excludes_hypothesized_claims_from_the_prompt_input():
    ssg = SecurityStateGraph()
    ssg.assert_claim("resolved", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("unresolved", "true", ClaimStatus.HYPOTHESIZED)

    captured = {}

    def fake_chat_json(messages, max_tokens=None, seed=None):
        captured["user_message"] = messages[1]["content"]
        return {"behavioral_insights": [], "security_insights": [], "knowledge_gaps": []}

    with patch("aginiti.core.graph.insights.chat_json", side_effect=fake_chat_json):
        synthesize_insights(ssg, target_name="test-target")

    assert "resolved" in captured["user_message"]
    assert "unresolved" not in captured["user_message"]


def test_synthesize_insights_warns_instead_of_silently_swallowing_a_parse_error():
    # 2026-08-09 fix: live-diagnosed real bug -- a truncated/malformed
    # chat_json response (the {"_parse_error": True, "_raw": ...} fallback,
    # aginiti/llm_client.py + gemini_client.py) was previously
    # indistinguishable from "the model had nothing to report" all the way
    # up to the Target Profile. Must now warn, not raise (a single failed
    # synthesis call still must not crash an otherwise-fine campaign) --
    # and must still return [] (no fabricated insights from garbage input).
    import warnings

    ssg = SecurityStateGraph()
    ssg.assert_claim("resolved", "true", ClaimStatus.CONFIRMED)

    def fake_chat_json(messages, max_tokens=None, seed=None):
        return {"_parse_error": True, "_raw": '{"behavioral_insights": [{"statement": "cut off mid'}

    with patch("aginiti.core.graph.insights.chat_json", side_effect=fake_chat_json):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = synthesize_insights(ssg, target_name="test-target")

    assert result == []
    assert any("parse" in str(w.message).lower() for w in caught)


def test_synthesize_insights_does_not_warn_on_a_genuinely_empty_but_valid_verdict():
    # A real "nothing to report" verdict (empty lists, no _parse_error) must
    # NOT trigger the same warning -- only an actual parse failure should.
    import warnings

    ssg = SecurityStateGraph()
    ssg.assert_claim("resolved", "true", ClaimStatus.CONFIRMED)

    def fake_chat_json(messages, max_tokens=None, seed=None):
        return {"behavioral_insights": [], "security_insights": [], "knowledge_gaps": []}

    with patch("aginiti.core.graph.insights.chat_json", side_effect=fake_chat_json):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            synthesize_insights(ssg, target_name="test-target")

    assert not any("parse" in str(w.message).lower() for w in caught)


def test_synthesize_insights_handles_malformed_verdict_shape_gracefully():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)

    with patch("aginiti.core.graph.insights.chat_json", return_value={"behavioral_insights": "not a list"}):
        result = synthesize_insights(ssg, target_name="test-target")

    assert result == []


def test_repeated_synthesis_does_not_duplicate_a_behavioral_insight_with_the_same_grounding():
    # Regression test: run_understanding_loop re-synthesizes from the full
    # claim set every round, so the same still-true claims stay in the
    # input round after round -- without dedup, a real live run produced
    # a dozen near-identical restatements of one finding across 7 rounds.
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("k2", "true", ClaimStatus.CONFIRMED)
    fake_verdict = {
        "behavioral_insights": [{"statement": "the agent does X", "claim_keys": ["k1", "k2"]}],
        "security_insights": [], "knowledge_gaps": [],
    }

    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        first = synthesize_insights(ssg, target_name="test-target")
        second = synthesize_insights(ssg, target_name="test-target")  # same claims, same "finding" again

    assert len(first) == 1
    assert second == []  # nothing new recorded -- already have this exact grounded finding
    assert len(ssg.insights) == 1


def test_a_different_grounding_set_is_not_treated_as_a_duplicate():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("k2", "true", ClaimStatus.CONFIRMED)
    verdict_a = {"behavioral_insights": [{"statement": "finding a", "claim_keys": ["k1"]}],
                 "security_insights": [], "knowledge_gaps": []}
    verdict_b = {"behavioral_insights": [{"statement": "finding b", "claim_keys": ["k1", "k2"]}],
                 "security_insights": [], "knowledge_gaps": []}

    with patch("aginiti.core.graph.insights.chat_json", side_effect=[verdict_a, verdict_b]):
        first = synthesize_insights(ssg, target_name="test-target")
        second = synthesize_insights(ssg, target_name="test-target")

    assert len(first) == 1
    assert len(second) == 1  # different grounding set -- genuinely new, not a repeat
    assert len(ssg.insights) == 2


def test_repeated_synthesis_does_not_duplicate_a_knowledge_gap_with_the_same_topic():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{"topic": "Persistent Memory", "why_it_matters": "unknown", "importance": "high"}],
    }

    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        first = synthesize_insights(ssg, target_name="test-target")
        # Slightly different wording/case on the topic, same underlying gap.
        second = synthesize_insights(ssg, target_name="test-target")

    assert len(first) == 1
    assert second == []
    assert len(ssg.insights) == 1


def test_gap_with_prior_belief_and_matched_probe_forms_a_hypothesis():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([
        _op("probe_memory", description="check memory", understanding_question="does memory persist?",
            effects_success=(ClaimEffect("memory_persists", ClaimStatus.CONFIRMED),)),
    ])
    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{
            "topic": "memory persistence", "why_it_matters": "unknown", "importance": "high",
            "prior_belief": "probably persists memory", "prior_confidence": "medium",
        }],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        synthesize_insights(ssg, target_name="test-target", library=library)

    assert len(ssg.hypotheses) == 1
    hyp = next(iter(ssg.hypotheses.values()))
    assert hyp.target_claim_key == "memory_persists"
    assert hyp.confidence == 0.65
    assert hyp.status == HypothesisStatus.OPEN


def test_gap_without_prior_belief_does_not_form_a_hypothesis():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([
        _op("probe_memory", effects_success=(ClaimEffect("memory_persists", ClaimStatus.CONFIRMED),)),
    ])
    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{"topic": "memory persistence", "why_it_matters": "unknown", "importance": "high"}],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        synthesize_insights(ssg, target_name="test-target", library=library)

    assert ssg.hypotheses == {}


def test_hypothesis_resolves_when_its_experiment_later_executes():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([
        _op("probe_memory", description="check memory", understanding_question="does memory persist?",
            effects_success=(ClaimEffect("memory_persists", ClaimStatus.CONFIRMED),)),
    ])
    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{
            "topic": "memory persistence", "why_it_matters": "unknown", "importance": "high",
            "prior_belief": "probably persists memory", "prior_confidence": "high",
        }],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        synthesize_insights(ssg, target_name="test-target", library=library)

    hyp = next(iter(ssg.hypotheses.values()))
    assert hyp.status == HypothesisStatus.OPEN

    # The experiment actually runs later and confirms the target claim.
    ssg.assert_claim("memory_persists", "true", ClaimStatus.CONFIRMED)

    assert hyp.status == HypothesisStatus.ACCEPTED


def test_no_hypothesis_formed_when_the_whole_chain_can_only_ever_hypothesize():
    # Regression test for a real bug found running the understanding loop
    # live against DVAA: a gap matched to a recon-style operator whose
    # ONLY declared effect is HYPOTHESIZED (never CONFIRMED/REFUTED), with
    # nothing else in the library it could unlock, would form a hypothesis
    # that could NEVER resolve -- permanently stuck at its prior confidence.
    # Better to not form one than form a stuck one. (Renamed from "matched
    # probe" now that matching alone isn't the whole story -- see the chain
    # test below.)
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([
        _op("probe_recon_only", description="plant something", understanding_question="does it accept it?",
            effects_success=(ClaimEffect("accepts_instruction", ClaimStatus.HYPOTHESIZED),)),
    ])
    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{
            "topic": "memory persistence", "why_it_matters": "unknown", "importance": "high",
            "prior_belief": "probably persists memory", "prior_confidence": "high",
        }],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        synthesize_insights(ssg, target_name="test-target", library=library)

    assert ssg.hypotheses == {}


def test_hypothesis_forms_through_a_plant_then_recall_chain():
    # The fix for the limitation the test above's original name referenced:
    # the matched operator ("plant") only ever hypothesizes on its own, but
    # it unlocks "recall" (recall's precondition is plant's effect key),
    # and recall CAN resolve to CONFIRMED. A hypothesis should now form
    # targeting recall's claim key, with the whole chain -- both plant and
    # recall -- recorded as experiments, not just whichever operator matched.
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([
        _op("probe_memory_plant", description="plant an instruction into memory",
            understanding_question="does memory persist?",
            effects_success=(ClaimEffect("accepts_instruction", ClaimStatus.HYPOTHESIZED),)),
        _op("probe_memory_recall", description="recall the planted instruction later",
            understanding_question="does the planted instruction resurface?",
            effects_success=(ClaimEffect("memory_persists", ClaimStatus.CONFIRMED),),
            preconditions=(Precondition("accepts_instruction", ClaimStatus.HYPOTHESIZED),)),
    ])
    fake_verdict = {
        "behavioral_insights": [], "security_insights": [],
        "knowledge_gaps": [{
            "topic": "memory persistence", "why_it_matters": "unknown", "importance": "high",
            "prior_belief": "probably persists memory", "prior_confidence": "high",
        }],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        synthesize_insights(ssg, target_name="test-target", library=library)

    assert len(ssg.hypotheses) == 1
    hyp = next(iter(ssg.hypotheses.values()))
    assert hyp.target_claim_key == "memory_persists"  # recall's key, not plant's
    assert hyp.experiments == ("probe_memory_plant", "probe_memory_recall")
    assert hyp.status == HypothesisStatus.OPEN

    # The chain actually resolving it later still works end to end.
    ssg.assert_claim("memory_persists", "true", ClaimStatus.CONFIRMED)
    assert hyp.status == HypothesisStatus.ACCEPTED


def test_resolving_chain_search_is_bounded_by_max_depth():
    from aginiti.core.graph.insights import _find_resolving_chain

    # A chain of 6 hops, each only unlocking the next, none resolvable --
    # default max_depth=4 should give up rather than searching forever.
    ops = []
    for i in range(6):
        key = f"step_{i}_done"
        precond = (Precondition(f"step_{i - 1}_done", ClaimStatus.HYPOTHESIZED),) if i > 0 else ()
        ops.append(_op(f"step_{i}", effects_success=(ClaimEffect(key, ClaimStatus.HYPOTHESIZED),),
                       preconditions=precond))
    library = OperatorLibrary(ops)

    effect, chain = _find_resolving_chain(ops[0], library)

    assert effect is None
    assert chain == ()
