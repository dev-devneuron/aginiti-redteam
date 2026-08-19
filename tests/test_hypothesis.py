"""Tests for the Hypothesis object (aginiti/graph/hypothesis.py) -- the
first mutable, persistent-identity object in the graph. Pure logic, no
graph/adapter involved.
"""
from aginiti.core.graph.hypothesis import Hypothesis, HypothesisStatus, normalize_statement
from aginiti.core.graph.schema import ClaimStatus


def _hyp(confidence=0.5, expected=ClaimStatus.CONFIRMED):
    return Hypothesis.create("test hypothesis", "target_key", expected, ("probe_a",), confidence)


def test_normalize_statement_collapses_trivial_rewording():
    a = normalize_statement("The Agent Probably Persists Memory!")
    b = normalize_statement("the agent probably persists memory")
    assert a == b


def test_matching_status_increases_confidence_and_records_supporting_evidence():
    hyp = _hyp(confidence=0.5)
    hyp.apply_claim_status(ClaimStatus.CONFIRMED)
    assert hyp.confidence == 0.75
    assert hyp.supporting_evidence == ("target_key",)
    assert hyp.contradicting_evidence == ()


def test_opposite_status_decreases_confidence_and_records_contradicting_evidence():
    hyp = _hyp(confidence=0.5)
    hyp.apply_claim_status(ClaimStatus.REFUTED)
    assert hyp.confidence == 0.25
    assert hyp.contradicting_evidence == ("target_key",)
    assert hyp.supporting_evidence == ()


def test_hypothesized_status_does_not_move_confidence():
    hyp = _hyp(confidence=0.5)
    hyp.apply_claim_status(ClaimStatus.HYPOTHESIZED)
    assert hyp.confidence == 0.5
    assert hyp.status == HypothesisStatus.OPEN
    assert hyp.supporting_evidence == () and hyp.contradicting_evidence == ()


def test_confidence_crossing_accept_threshold_resolves_to_accepted():
    hyp = _hyp(confidence=0.6)  # one more supporting step -> 0.85, crosses 0.8
    hyp.apply_claim_status(ClaimStatus.CONFIRMED)
    assert hyp.status == HypothesisStatus.ACCEPTED


def test_confidence_crossing_reject_threshold_resolves_to_rejected():
    hyp = _hyp(confidence=0.4)  # one more contradicting step -> 0.15, crosses 0.2
    hyp.apply_claim_status(ClaimStatus.REFUTED)
    assert hyp.status == HypothesisStatus.REJECTED


def test_confidence_is_clamped_to_zero_and_one():
    hyp = _hyp(confidence=0.95)
    hyp.apply_claim_status(ClaimStatus.CONFIRMED)
    assert hyp.confidence == 1.0
    hyp2 = _hyp(confidence=0.05)
    hyp2.apply_claim_status(ClaimStatus.REFUTED)
    assert hyp2.confidence == 0.0


def test_resolved_hypothesis_no_longer_updates():
    hyp = _hyp(confidence=0.95)
    hyp.apply_claim_status(ClaimStatus.CONFIRMED)  # resolves ACCEPTED at confidence 1.0
    assert hyp.status == HypothesisStatus.ACCEPTED
    hyp.apply_claim_status(ClaimStatus.REFUTED)  # must be a no-op now
    assert hyp.confidence == 1.0
    assert hyp.contradicting_evidence == ()


def test_uncertainty_is_maximal_at_confidence_half():
    hyp = _hyp(confidence=0.5)
    assert hyp.uncertainty == 1.0


def test_uncertainty_is_zero_once_resolved():
    hyp = _hyp(confidence=0.95)
    hyp.apply_claim_status(ClaimStatus.CONFIRMED)  # resolves
    assert hyp.uncertainty == 0.0


def test_uncertainty_decreases_as_confidence_moves_away_from_half_while_still_open():
    hyp = _hyp(confidence=0.7)
    assert 0.0 < hyp.uncertainty < 1.0
    assert hyp.uncertainty < _hyp(confidence=0.5).uncertainty
