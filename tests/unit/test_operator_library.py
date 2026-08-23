"""OperatorLibrary.by_category() -- 2026-08-22 addition, added at explicit
user request for a proper category-level selector (the existing --tier
flag on scripts/run_campaign.py only exposes a coarse 3-bucket OWASP-
derived grouping, not the full 11-category attack_category taxonomy
directly).

Deliberately does NOT re-derive "which category does this operator
represent" here -- it exercises the real
aginiti.core.graph.attack_category.operator_primary_family() the method
itself calls, so these tests are also an indirect regression guard on
that function's own success-then-failure-effect fallback behavior, not
just on by_category()'s filtering logic layered on top of it.
"""
from aginiti.core.graph.attack_category import (
    DIRECT_PROMPT_ATTACK, ENCODING_ATTACK, RAG_POISONING, TOOL_DISCOVERY,
)
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary


def _op(op_id, success_attack_category=None, failure_attack_category=None):
    """A minimal, otherwise-inert Operator -- only the attack_category
    tag(s) under test vary between instances."""
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=(
            ClaimEffect(f"{op_id}_claim", ClaimStatus.CONFIRMED,
                        attack_category=success_attack_category),
        ) if success_attack_category is not None or failure_attack_category is None else (),
        effects_failure=(
            ClaimEffect(f"{op_id}_blocked", ClaimStatus.REFUTED,
                        attack_category=failure_attack_category),
        ) if failure_attack_category is not None else (),
        cost_prompts=1, risk_tier=RiskTier.LOW,
    )


def _library():
    return OperatorLibrary([
        _op("direct1", success_attack_category=DIRECT_PROMPT_ATTACK),
        _op("direct2", success_attack_category=DIRECT_PROMPT_ATTACK),
        _op("encoding1", success_attack_category=ENCODING_ATTACK),
        _op("rag1", success_attack_category=RAG_POISONING),
        # Only its FAILURE effect is tagged -- operator_primary_family()
        # must fall back to it, per that function's own documented
        # success-then-failure rule.
        _op("recon_via_failure_tag", failure_attack_category=TOOL_DISCOVERY),
        # Untagged entirely -- must never match any category.
        _op("untagged"),
    ])


def test_filters_to_a_single_category():
    result = _library().by_category(DIRECT_PROMPT_ATTACK)
    assert {op.id for op in result} == {"direct1", "direct2"}


def test_filters_to_multiple_categories_as_a_union():
    result = _library().by_category(ENCODING_ATTACK, RAG_POISONING)
    assert {op.id for op in result} == {"encoding1", "rag1"}


def test_matches_via_the_failure_effect_fallback_operator_primary_family_uses():
    result = _library().by_category(TOOL_DISCOVERY)
    assert {op.id for op in result} == {"recon_via_failure_tag"}


def test_untagged_operators_never_match_any_category():
    result = _library().by_category(DIRECT_PROMPT_ATTACK, ENCODING_ATTACK, RAG_POISONING, TOOL_DISCOVERY)
    assert "untagged" not in {op.id for op in result}


def test_returns_a_new_library_without_mutating_the_original():
    original = _library()
    original_ids = {op.id for op in original}
    filtered = original.by_category(DIRECT_PROMPT_ATTACK)
    assert filtered is not original
    assert {op.id for op in original} == original_ids  # unchanged
    assert len(filtered) == 2


def test_a_category_present_in_the_taxonomy_but_absent_from_this_library_returns_empty_not_an_error():
    from aginiti.core.graph.attack_category import MULTI_STEP_CHAIN
    result = _library().by_category(MULTI_STEP_CHAIN)
    assert len(result) == 0


def test_no_categories_given_raises_immediately():
    import pytest
    with pytest.raises(ValueError, match="at least one category"):
        _library().by_category()


def test_unknown_category_name_raises_with_a_helpful_message_not_silently_empty():
    import pytest
    with pytest.raises(ValueError, match="Unknown attack_category"):
        _library().by_category("not_a_real_category")
