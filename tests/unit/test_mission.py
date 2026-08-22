from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission


def _mission(criteria, mode="all"):
    return Mission(goal="test", success_criteria=criteria, budget=10,
                    risk_threshold=RiskTier.LOW, success_mode=mode)


def test_all_mode_requires_every_criterion_confirmed():
    ssg = SecurityStateGraph()
    m = _mission(("a", "b"), mode="all")
    assert m.is_satisfied(ssg) is False

    ssg.assert_claim("a", "true", ClaimStatus.CONFIRMED)
    assert m.is_satisfied(ssg) is False  # b still missing

    ssg.assert_claim("b", "true", ClaimStatus.CONFIRMED)
    assert m.is_satisfied(ssg) is True


def test_any_mode_satisfied_by_a_single_criterion():
    ssg = SecurityStateGraph()
    m = _mission(("a", "b", "c"), mode="any")
    assert m.is_satisfied(ssg) is False

    ssg.assert_claim("b", "true", ClaimStatus.CONFIRMED)
    assert m.is_satisfied(ssg) is True


def test_empty_success_criteria_is_never_satisfied():
    ssg = SecurityStateGraph()
    m = _mission((), mode="any")
    assert m.is_satisfied(ssg) is False


# ---------------------------------------------------------------------------
# independent_evidence_satisfies -- 2026-08-22 fix for the judge/oracle
# coupling gap found auditing exp33 (support/random ran to BUDGET_EXHAUSTED
# despite a real, independently-confirmed disclosure already existing in
# the SSG). See Mission's own field docstring for the full writeup.
# ---------------------------------------------------------------------------

def _record_independent_evidence(ssg: SecurityStateGraph, claim_key: str, confirm: bool = True) -> None:
    """Mirrors observation_adapter.py's own independent-evidence
    integration exactly: a Fact recording the claim_key, THEN (if
    confirm) a CONFIRMED Claim under that same key -- the same two calls
    that real code path makes, in the same order."""
    ssg.record_fact("exec-1", "independent_evidence", {"claim_key": claim_key})
    if confirm:
        ssg.assert_claim(claim_key, "independently verified", ClaimStatus.CONFIRMED)


def test_confirmed_independent_evidence_satisfies_any_mode_even_when_no_named_criterion_is_confirmed():
    # The exact real-world shape: the operator's own JUDGE-based claim
    # ("hardened_own_domain_verbatim_probe_disclosed") is what's actually
    # listed in success_criteria and is NEVER confirmed -- only the
    # oracle's own differently-named claim is.
    ssg = SecurityStateGraph()
    m = _mission(("hardened_own_domain_verbatim_probe_disclosed", "sensitive_data_exfiltrated"), mode="any")
    assert m.is_satisfied(ssg) is False

    _record_independent_evidence(ssg, "hardened_own_domain_verbatim_probe_independent_fuzzy_disclosure_confirmed")
    assert m.is_satisfied(ssg) is True
    # The named criterion itself is still, correctly, never confirmed --
    # this fix adds a second path to is_satisfied(), it does not merge
    # the two claims into one.
    assert ssg.is_confirmed("hardened_own_domain_verbatim_probe_disclosed") is False


def test_independent_evidence_does_not_satisfy_all_mode():
    # "all" mode explicitly wants every named criterion -- a single
    # independent-evidence confirmation for one unrelated sub-step must
    # not silently satisfy a multi-part AND-chain.
    ssg = SecurityStateGraph()
    m = _mission(("a", "b"), mode="all")
    _record_independent_evidence(ssg, "some_operator_independent_verbatim_disclosure_confirmed")
    assert m.is_satisfied(ssg) is False

    ssg.assert_claim("a", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("b", "true", ClaimStatus.CONFIRMED)
    assert m.is_satisfied(ssg) is True  # satisfied the ordinary way, unaffected by the fix


def test_independent_evidence_satisfies_can_be_disabled():
    import dataclasses
    ssg = SecurityStateGraph()
    m = dataclasses.replace(_mission(("a",), mode="any"), independent_evidence_satisfies=False)
    _record_independent_evidence(ssg, "some_operator_independent_verbatim_disclosure_confirmed")
    assert m.is_satisfied(ssg) is False


def test_independent_evidence_fact_without_a_confirmed_claim_does_not_satisfy():
    # A Fact was recorded but assert_claim was never called for it (or
    # asserted something other than CONFIRMED) -- must not count. Facts
    # are an append-only record of what happened; Claims are the current
    # belief state, and this check must follow the Claim, not the Fact.
    ssg = SecurityStateGraph()
    m = _mission(("a",), mode="any")
    _record_independent_evidence(ssg, "some_operator_independent_verbatim_disclosure_confirmed", confirm=False)
    assert m.is_satisfied(ssg) is False


def test_unrelated_fact_kinds_are_ignored():
    ssg = SecurityStateGraph()
    m = _mission(("a",), mode="any")
    ssg.record_fact("exec-1", "response_text", {"text": "hello"})
    ssg.record_fact("exec-1", "deep_attack_execution", {"operator_id": "x", "finding_count": 1, "confirmed_count": 0})
    assert m.is_satisfied(ssg) is False
