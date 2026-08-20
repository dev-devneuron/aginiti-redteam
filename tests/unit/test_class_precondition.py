"""ClassPrecondition (aginiti/operators/library.py) -- the semantic-class
precondition-matching mechanism behind multi-step attack-path discovery
without human-hardcoded exact-key chains. See discovery_chain_definitions.py
and experiments/discovery_chain_dry_run.py for the end-to-end demonstration;
these tests isolate the matching primitive itself."""
from __future__ import annotations

import pytest

from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.security_boundary import BOUNDARY_L2, BOUNDARY_L4
from aginiti.core.graph.ssg import CATEGORY_TRUST_EDGE, SecurityStateGraph
from aginiti.operators.library import ClaimEffect, ClassPrecondition, Operator

CONFIRMED = ClaimStatus.CONFIRMED


def _op_with_class_precondition(cpre: ClassPrecondition) -> Operator:
    return Operator(
        id="downstream", description="x", prompt="x", channel="direct",
        preconditions=(), precondition_classes=(cpre,),
        effects_success=(ClaimEffect("downstream_done", CONFIRMED),), effects_failure=(),
        cost_prompts=1, risk_tier=RiskTier.LOW,
    )


def test_class_precondition_requires_at_least_one_field():
    with pytest.raises(ValueError):
        ClassPrecondition()


def test_category_class_precondition_matched_by_any_key_with_that_category():
    ssg = SecurityStateGraph()
    op = _op_with_class_precondition(ClassPrecondition(category=CATEGORY_TRUST_EDGE))
    assert not op.preconditions_met(ssg)

    # A key the operator author never named or predicted still satisfies it,
    # purely because it carries the matching category tag.
    ssg.assert_claim("some_totally_unrelated_key", "true", CONFIRMED, category=CATEGORY_TRUST_EDGE)
    assert op.preconditions_met(ssg)


def test_category_class_precondition_ignores_non_matching_category():
    ssg = SecurityStateGraph()
    op = _op_with_class_precondition(ClassPrecondition(category=CATEGORY_TRUST_EDGE))
    ssg.assert_claim("k", "true", CONFIRMED, category="capability")
    assert not op.preconditions_met(ssg)


def test_attack_category_class_precondition():
    ssg = SecurityStateGraph()
    op = _op_with_class_precondition(ClassPrecondition(attack_category="rag_poisoning"))
    assert not op.preconditions_met(ssg)
    ssg.assert_claim("k", "true", CONFIRMED, attack_category="rag_poisoning")
    assert op.preconditions_met(ssg)


def test_min_security_boundary_rank_class_precondition_is_satisfied_by_higher_ranks_too():
    ssg = SecurityStateGraph()
    op = _op_with_class_precondition(ClassPrecondition(min_security_boundary_rank=2))  # L2
    ssg.assert_claim("k", "true", CONFIRMED, security_boundary=BOUNDARY_L4)  # rank 4 >= 2
    assert op.preconditions_met(ssg)


def test_min_security_boundary_rank_class_precondition_rejects_lower_ranks():
    ssg = SecurityStateGraph()
    op = _op_with_class_precondition(ClassPrecondition(min_security_boundary_rank=4))  # L4
    ssg.assert_claim("k", "true", CONFIRMED, security_boundary=BOUNDARY_L2)  # rank 2 < 4
    assert not op.preconditions_met(ssg)


def test_class_precondition_ignores_refuted_claims():
    ssg = SecurityStateGraph()
    op = _op_with_class_precondition(ClassPrecondition(category=CATEGORY_TRUST_EDGE))
    ssg.assert_claim("k", "true", ClaimStatus.REFUTED, category=CATEGORY_TRUST_EDGE)
    assert not op.preconditions_met(ssg)


def test_class_precondition_respects_status_when_not_hypothesized_wildcard():
    ssg = SecurityStateGraph()
    op = _op_with_class_precondition(ClassPrecondition(category=CATEGORY_TRUST_EDGE, status=CONFIRMED))
    ssg.assert_claim("k", "true", ClaimStatus.HYPOTHESIZED, category=CATEGORY_TRUST_EDGE)
    assert not op.preconditions_met(ssg)  # only hypothesized, not confirmed
    ssg.assert_claim("k", "true", CONFIRMED, category=CATEGORY_TRUST_EDGE)
    assert op.preconditions_met(ssg)


def test_combined_category_and_attack_category_is_an_and_not_an_or():
    ssg = SecurityStateGraph()
    op = _op_with_class_precondition(
        ClassPrecondition(category=CATEGORY_TRUST_EDGE, attack_category="tool_manipulation")
    )
    # Matches category alone -- not enough.
    ssg.assert_claim("k1", "true", CONFIRMED, category=CATEGORY_TRUST_EDGE, attack_category="rag_poisoning")
    assert not op.preconditions_met(ssg)
    # A DIFFERENT key matches both fields together -- satisfied.
    ssg.assert_claim("k2", "true", CONFIRMED, category=CATEGORY_TRUST_EDGE, attack_category="tool_manipulation")
    assert op.preconditions_met(ssg)


def test_exact_key_and_class_preconditions_are_anded_together():
    from aginiti.operators.library import Precondition

    ssg = SecurityStateGraph()
    op = Operator(
        id="mixed", description="x", prompt="x", channel="direct",
        preconditions=(Precondition("exact_key", CONFIRMED),),
        precondition_classes=(ClassPrecondition(category=CATEGORY_TRUST_EDGE),),
        effects_success=(ClaimEffect("mixed_done", CONFIRMED),), effects_failure=(),
        cost_prompts=1, risk_tier=RiskTier.LOW,
    )
    ssg.assert_claim("exact_key", "true", CONFIRMED)  # exact satisfied, class not
    assert not op.preconditions_met(ssg)
    ssg.assert_claim("some_key", "true", CONFIRMED, category=CATEGORY_TRUST_EDGE)  # now both satisfied
    assert op.preconditions_met(ssg)
