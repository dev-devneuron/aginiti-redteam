"""Tests for translate_findings_to_claims (aginiti/core/finding_translation.py,
Phase 2 Slice C). Pure function, zero campaign/SSG/operator dependency --
no mocking needed beyond constructing LeakFinding fixtures directly."""
import pytest

from aginiti.attacks.base import LeakFinding
from aginiti.core.finding_translation import translate_findings_to_claims
from aginiti.core.graph.schema import ClaimStatus


def _finding(confirmed: bool, **overrides) -> LeakFinding:
    defaults = dict(
        attack_type="DRA",
        tier_used="black_box",
        confidence=0.85 if confirmed else 0.2,
        confirmed=confirmed,
        leaked_content="some evidence" if confirmed else "",
        probe_used="a probe",
        trace_span_id="",
        recommendation="",
        severity="high" if confirmed else "low",
    )
    defaults.update(overrides)
    return LeakFinding(**defaults)


# ---------------------------------------------------------------------------
# Table-driven: the three real decision branches
# ---------------------------------------------------------------------------

def test_empty_findings_asserts_nothing():
    assert translate_findings_to_claims([], claim_key="system_prompt_disclosed") is None


def test_single_confirmed_finding_yields_confirmed():
    result = translate_findings_to_claims(
        [_finding(confirmed=True)], claim_key="system_prompt_disclosed"
    )
    assert result == ClaimStatus.CONFIRMED


def test_single_unconfirmed_finding_yields_hypothesized():
    # A non-refused response present in `findings` at all (per
    # IKEAAttack.execute_black_box's own routing) that didn't clear the
    # attack's confirmed-leak-type bar -- still positive-but-provisional
    # evidence, not nothing and not a refutation.
    result = translate_findings_to_claims(
        [_finding(confirmed=False)], claim_key="system_prompt_disclosed"
    )
    assert result == ClaimStatus.HYPOTHESIZED


@pytest.mark.parametrize("findings, expected", [
    ([], None),
    ([_finding(confirmed=False)], ClaimStatus.HYPOTHESIZED),
    ([_finding(confirmed=False), _finding(confirmed=False)], ClaimStatus.HYPOTHESIZED),
    ([_finding(confirmed=True)], ClaimStatus.CONFIRMED),
    ([_finding(confirmed=True), _finding(confirmed=True)], ClaimStatus.CONFIRMED),
    # Mixed: ANY confirmed finding is enough, regardless of how many other
    # findings in the same run were inconclusive.
    ([_finding(confirmed=False), _finding(confirmed=True)], ClaimStatus.CONFIRMED),
    ([_finding(confirmed=True), _finding(confirmed=False), _finding(confirmed=False)],
     ClaimStatus.CONFIRMED),
])
def test_decision_table(findings, expected):
    assert translate_findings_to_claims(findings, claim_key="system_prompt_disclosed") == expected


# ---------------------------------------------------------------------------
# Never returns REFUTED — the deliberate Open Question 4 decision
# ---------------------------------------------------------------------------

def test_never_returns_refuted_regardless_of_input_shape():
    # Empty findings and all-unconfirmed findings are the two cases most
    # likely to tempt a REFUTED result -- explicitly locked to never happen,
    # since an empty list is genuinely ambiguous (see this test module's
    # own module docstring reference) and this bridge has no way to tell
    # "no leak" apart from "every probe refused" from findings alone.
    assert translate_findings_to_claims([], claim_key="k") != ClaimStatus.REFUTED
    assert translate_findings_to_claims(
        [_finding(confirmed=False)], claim_key="k"
    ) != ClaimStatus.REFUTED
    assert translate_findings_to_claims(
        [_finding(confirmed=False)] * 5, claim_key="k"
    ) != ClaimStatus.REFUTED


# ---------------------------------------------------------------------------
# claim_key is documentation/logging only, never filters the decision
# ---------------------------------------------------------------------------

def test_claim_key_value_never_changes_the_decision():
    findings = [_finding(confirmed=True)]
    assert (
        translate_findings_to_claims(findings, claim_key="system_prompt_disclosed")
        == translate_findings_to_claims(findings, claim_key="totally_unrelated_key")
        == ClaimStatus.CONFIRMED
    )


def test_claim_key_is_keyword_only():
    with pytest.raises(TypeError):
        translate_findings_to_claims([], "system_prompt_disclosed")  # type: ignore[misc]
