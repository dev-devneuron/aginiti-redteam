"""Regression tests for the claim-category taxonomy (trust_edge/capability/
workflow/mission_outcome/defender_control) -- what makes "which trust
assumptions did the agent reveal" answerable as a direct query instead of
eyeballing claim keys. No live API calls.
"""
from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import (
    CATEGORY_CAPABILITY,
    CATEGORY_DEFENDER_CONTROL,
    CATEGORY_TRUST_EDGE,
    SUBGRAPH_DEFENDER,
    SUBGRAPH_TARGET,
    SecurityStateGraph,
)
from aginiti.operators.library import ClaimEffect


def test_target_subgraph_effect_defaults_to_capability_category():
    effect = ClaimEffect("some_key", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET)
    assert effect.category == CATEGORY_CAPABILITY


def test_defender_subgraph_effect_defaults_to_defender_control_category():
    effect = ClaimEffect("blocked", ClaimStatus.CONFIRMED, SUBGRAPH_DEFENDER)
    assert effect.category == CATEGORY_DEFENDER_CONTROL


def test_explicit_category_is_not_overridden_by_the_default_inference():
    effect = ClaimEffect("trusts_x", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET, category=CATEGORY_TRUST_EDGE)
    assert effect.category == CATEGORY_TRUST_EDGE


def test_assert_claim_records_category_and_leaves_it_on_later_uncategorized_calls():
    ssg = SecurityStateGraph()
    ssg.assert_claim("trusts_slack", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    assert ssg.claim_category["trusts_slack"] == CATEGORY_TRUST_EDGE

    # A later assert_claim on the same key with no category passed (e.g.
    # the auto-hypothesize path in _recompute_confidence) must not erase
    # the tag that was already recorded for this key.
    ssg.assert_claim("trusts_slack", "true", ClaimStatus.REFUTED)
    assert ssg.claim_category["trusts_slack"] == CATEGORY_TRUST_EDGE
