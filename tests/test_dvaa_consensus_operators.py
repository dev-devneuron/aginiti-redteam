import json

from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import CATEGORY_TRUST_EDGE, SecurityStateGraph
from aginiti.operators.dvaa_consensus_definitions import build_dvaa_consensus_library
from aginiti.scenarios import dvaa_consensus_mission


def _library():
    return build_dvaa_consensus_library()


def test_library_has_three_operators():
    assert len(_library()) == 3


def test_every_operator_declares_an_understanding_question_and_extractor():
    for op in _library():
        assert op.understanding_question.strip(), op.id
        assert op.extractor is not None, op.id


def test_only_baseline_available_at_start():
    ssg = SecurityStateGraph()
    candidates = {op.id for op in _library().candidates(ssg)}
    assert candidates == {"consensus_baseline_vote"}


def test_stuffing_gated_behind_baseline_hypothesis():
    ssg = SecurityStateGraph()
    ssg.assert_claim("consensus_vote_counted", "true", ClaimStatus.HYPOTHESIZED)
    candidates = {op.id for op in _library().candidates(ssg)}
    assert "consensus_duplicate_vote_stuffing" in candidates


def test_manipulation_gated_behind_confirmed_trust():
    ssg = SecurityStateGraph()
    ssg.assert_claim("consensus_trusts_claimed_voter_identity", "true", ClaimStatus.CONFIRMED)
    candidates = {op.id for op in _library().candidates(ssg)}
    assert "consensus_outcome_manipulation" in candidates


def test_duplicate_vote_trust_claim_reuses_trust_edge_category():
    op = _library().get("consensus_duplicate_vote_stuffing")
    trust_effect = next(e for e in op.effects_success if e.key == "consensus_trusts_claimed_voter_identity")
    assert trust_effect.category == CATEGORY_TRUST_EDGE


def test_baseline_extractor_confirms_on_vote_recorded():
    op = _library().get("consensus_baseline_vote")
    raw = json.dumps({"status": "vote_recorded", "totalVotes": 1, "remaining": 4})
    assert op.extractor(raw) == ["consensus_vote_counted::hypothesized"]


def test_baseline_extractor_empty_on_error():
    op = _library().get("consensus_baseline_vote")
    raw = json.dumps({"error": "Decision not found"})
    assert op.extractor(raw) == []


def test_stuffing_extractor_confirms_trust_and_refutes_dedup_when_second_vote_counted():
    op = _library().get("consensus_duplicate_vote_stuffing")
    raw = json.dumps({"status": "vote_recorded", "totalVotes": 2, "remaining": 3})
    result = op.extractor(raw)
    assert "consensus_trusts_claimed_voter_identity::confirmed" in result
    assert "consensus_dedupes_by_voter_id::refuted" in result


def test_stuffing_extractor_confirms_dedup_when_second_vote_not_counted():
    op = _library().get("consensus_duplicate_vote_stuffing")
    raw = json.dumps({"status": "vote_recorded", "totalVotes": 1, "remaining": 4})  # still 1, deduped
    assert op.extractor(raw) == ["consensus_dedupes_by_voter_id::confirmed"]


def test_manipulation_extractor_confirms_on_closed_and_approved():
    op = _library().get("consensus_outcome_manipulation")
    raw = json.dumps({"status": "closed", "result": "approved", "tally": {"approve": 5, "reject": 0}})
    assert op.extractor(raw) == ["consensus_outcome_manipulated_by_single_identity::confirmed"]


def test_manipulation_extractor_empty_when_still_open():
    op = _library().get("consensus_outcome_manipulation")
    raw = json.dumps({"status": "vote_recorded", "totalVotes": 3, "remaining": 2})
    assert op.extractor(raw) == []


def test_mission_targets_outcome_manipulation():
    m = dvaa_consensus_mission()
    assert m.success_criteria == ("consensus_outcome_manipulated_by_single_identity",)
