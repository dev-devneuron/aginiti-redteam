from aginiti.core.graph.hypothesis import HypothesisStatus
from aginiti.core.graph.schema import ClaimStatus, ConfidenceBand
from aginiti.core.graph.ssg import SecurityStateGraph


def test_first_observation_hypothesizes_claim():
    ssg = SecurityStateGraph()
    ssg.record_observation("op_exec_1", "target mentions salary certificates", supports=("payroll_api_exists",))

    claim = ssg.current_claim("payroll_api_exists")
    assert claim is not None
    assert claim.status == ClaimStatus.HYPOTHESIZED
    assert claim.confidence == ConfidenceBand.LOW


def test_confirming_observation_raises_confidence_and_status():
    ssg = SecurityStateGraph()
    ssg.record_observation("op_exec_1", "target mentions salary certificates", supports=("payroll_api_exists",))
    ssg.record_observation("op_exec_2", "target confirms payroll endpoint reachable", supports=("payroll_api_exists",))
    ssg.assert_claim("payroll_api_exists", object_="true", status=ClaimStatus.CONFIRMED)

    claim = ssg.current_claim("payroll_api_exists")
    assert claim.status == ClaimStatus.CONFIRMED
    assert claim.confidence == ConfidenceBand.MEDIUM  # net score 2


def test_append_only_history_is_preserved():
    ssg = SecurityStateGraph()
    ssg.record_observation("op_exec_1", "sig1", supports=("k",))
    ssg.record_observation("op_exec_2", "sig2", supports=("k",))
    versions = [c for c in ssg.claims if c.key == "k"]
    assert len(versions) >= 2
    assert versions[-1].supersedes == versions[-2].id


def test_failed_operator_still_grows_defender_graph():
    ssg = SecurityStateGraph()
    ssg.record_observation("op_exec_1", "BLOCKED by filter", contradicts=("indirect_injection_via_slack",))
    ssg.assert_claim("prompt_filter_present", object_="true", status=ClaimStatus.CONFIRMED, subgraph="defender")

    ssg.record_operator_execution("indirect_prompt_injection", success=False)
    assert ssg.operator_stats["indirect_prompt_injection"].failures == 1
    assert any(c.key == "prompt_filter_present" for c in ssg.defender_claims())


def test_current_claim_returns_latest_by_key():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k", "v1", ClaimStatus.HYPOTHESIZED)
    ssg.assert_claim("k", "v2", ClaimStatus.CONFIRMED)
    assert ssg.current_claim("k").object == "v2"


def test_form_hypothesis_is_get_or_create_by_normalized_statement():
    ssg = SecurityStateGraph()
    first = ssg.form_hypothesis("the agent persists memory", "memory_persists", ClaimStatus.CONFIRMED,
                                 experiments=("probe_a",))
    second = ssg.form_hypothesis("The Agent Persists Memory.", "memory_persists", ClaimStatus.CONFIRMED,
                                  experiments=("probe_b",))

    assert first is second  # SAME tracked object, not a duplicate
    assert set(second.experiments) == {"probe_a", "probe_b"}  # experiment lists merged
    assert len(ssg.hypotheses) == 1


def test_assert_claim_automatically_updates_a_matching_open_hypothesis():
    ssg = SecurityStateGraph()
    hyp = ssg.form_hypothesis("agent persists memory", "memory_persists", ClaimStatus.CONFIRMED,
                               experiments=("probe_a",), prior_confidence=0.6)

    ssg.assert_claim("memory_persists", "true", ClaimStatus.CONFIRMED)  # the linked experiment resolving

    assert hyp.confidence == 0.85
    assert hyp.supporting_evidence == ("memory_persists",)


def test_assert_claim_can_reject_a_hypothesis_through_the_same_hook():
    ssg = SecurityStateGraph()
    hyp = ssg.form_hypothesis("agent persists memory", "memory_persists", ClaimStatus.CONFIRMED,
                               experiments=("probe_a",), prior_confidence=0.4)

    ssg.assert_claim("memory_persists", "true", ClaimStatus.REFUTED)

    assert hyp.status == HypothesisStatus.REJECTED


def test_form_hypothesis_applies_an_already_resolved_claim_immediately():
    # The linked experiment ran BEFORE this hypothesis was even formed
    # (e.g. synthesis catching up on an earlier round) -- it shouldn't
    # have to wait for a future assert_claim call that may never come.
    ssg = SecurityStateGraph()
    ssg.assert_claim("memory_persists", "true", ClaimStatus.CONFIRMED)

    hyp = ssg.form_hypothesis("agent persists memory", "memory_persists", ClaimStatus.CONFIRMED,
                               experiments=("probe_a",), prior_confidence=0.6)

    assert hyp.confidence == 0.85
    assert hyp.supporting_evidence == ("memory_persists",)


def test_unrelated_claim_does_not_affect_a_hypothesis_targeting_a_different_key():
    ssg = SecurityStateGraph()
    hyp = ssg.form_hypothesis("agent persists memory", "memory_persists", ClaimStatus.CONFIRMED,
                               experiments=("probe_a",), prior_confidence=0.5)

    ssg.assert_claim("unrelated_key", "true", ClaimStatus.CONFIRMED)

    assert hyp.confidence == 0.5
    assert hyp.status == HypothesisStatus.OPEN
