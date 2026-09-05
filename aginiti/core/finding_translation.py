"""LeakFinding -> ClaimStatus bridge (Phase 2 Slice C,
plans/phase2-operator-wrapping.md). Pure function, zero campaign/operator
dependency -- deliberately kept that way so this stays unit-testable in
complete isolation, ahead of Slice D wiring it into ObservationAdapter.

Design decision (plan doc, Claim Translation section, verified directly
against real attack code before committing to it): use LeakFinding.confirmed
directly, not a re-derived confidence threshold. `confirmed` already means
what this bridge needs -- "an actual data disclosure... not merely a
non-refused or topically-relevant response" (LeakFinding's own docstring,
aginiti/attacks/base.py) -- computed by each attack's own judge/classifier.
Re-deriving a fresh threshold from `confidence` would risk silently
disagreeing with a decision the attack already made; confirmed live in
IKEAAttack._make_finding that `confidence` is often DERIVED FROM severity
(`_severity_to_float(severity)`), not an independent signal, so a
threshold system built on it would really just be re-deriving severity
under a different name.

Empty-findings handling (Open Question 4, explicitly approved):
asserts nothing (returns None) rather than defaulting to REFUTED.
`IKEAAttack.execute_black_box` only appends to `findings` when a probe is
NOT refused (a refused probe goes to `attack.refused_queries` instead,
verified directly at ikea.py's main loop) -- so an empty `findings` list
is genuinely ambiguous between "tried and found nothing confirmed" and
"every probe was refused," and this bridge cannot tell those apart from
`findings` alone. Accepted consequence of that decision: `refused_queries`
stays unsurfaced to the planner in Phase 2, so "everything got refused"
does not (yet) feed AginitiPlanner's failure_evidence_penalty.
"""
from __future__ import annotations

from aginiti.attacks.base import LeakFinding
from aginiti.core.graph.schema import ClaimStatus
from aginiti.core.observability import get_logger

_logger = get_logger("core.finding_translation")


def translate_findings_to_claims(
    findings: list[LeakFinding],
    *,
    claim_key: str,
) -> ClaimStatus | None:
    """Decides the ClaimStatus a wrapped deep attack's findings support for
    one Operator's declared `claim_key` -- the caller (Slice D's
    `ObservationAdapter._execute_deep_attack`) is responsible for actually
    calling `ssg.assert_claim(claim_key, ..., status, ...)` with the
    result; this function only makes the CONFIRMED/HYPOTHESIZED/(assert
    nothing) decision, kept separate so it stays testable with zero SSG/
    campaign dependency.

    - `findings` empty -> None (assert nothing). See this module's own
      docstring for why REFUTED is deliberately never asserted here.
    - Any `finding.confirmed is True` -> ClaimStatus.CONFIRMED. One
      genuine confirmed disclosure is enough regardless of how many other
      findings in the same run were less conclusive -- matches the "a
      single response can independently support" spirit
      ObservationAdapter._judge's own prompt already applies to ordinary
      prompt-type operators.
    - `findings` non-empty but none confirmed -> ClaimStatus.HYPOTHESIZED.
      A non-refused response that didn't clear the attack's own
      confirmed-leak-type bar is still provisional positive evidence
      (matches ObservationAdapter's own HYPOTHESIZED-is-still-positive-
      evidence convention for effects like `payroll_api_exists`), not
      nothing and not a refutation.

    `claim_key` does not filter or otherwise change the decision --
    `LeakFinding` has no claim-key concept of its own (a deep-attack
    Operator is scoped to exactly one claim_key by construction, so every
    finding a wrapped attack returns is already implicitly "about" that
    key). It exists so the log line below identifies which claim a given
    decision was for, matching this project's own observability
    conventions elsewhere (e.g. ObservationAdapter's own confirmed-finding
    log line)."""
    if not findings:
        _logger.info(
            "finding_translation: claim_key=%s -- 0 findings, asserting nothing "
            "(ambiguous between 'no leak' and 'every probe refused')",
            claim_key,
        )
        return None

    confirmed_count = sum(1 for f in findings if f.confirmed)
    if confirmed_count > 0:
        _logger.warning(
            "finding_translation: claim_key=%s -- CONFIRMED (%d/%d findings confirmed)",
            claim_key, confirmed_count, len(findings),
        )
        return ClaimStatus.CONFIRMED

    _logger.info(
        "finding_translation: claim_key=%s -- HYPOTHESIZED (%d non-refused finding(s), "
        "none cleared the attack's own confirmed-leak-type bar)",
        claim_key, len(findings),
    )
    return ClaimStatus.HYPOTHESIZED
