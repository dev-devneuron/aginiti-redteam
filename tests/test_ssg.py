from aginiti.graph.schema import ClaimStatus, ConfidenceBand
from aginiti.graph.ssg import SecurityStateGraph


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
