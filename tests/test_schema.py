"""Tests for aginiti/graph/schema.py's Insight -- specifically the
priority_weight/importance consistency check added 2026-08-09 in response
to an internal-audit finding: the "never crosses a bucket boundary" safety
property priority_weight exists to guarantee was previously enforced only
by the one caller (priors.py) that computes it correctly, not by the
schema itself.
"""
import pytest

from aginiti.core.graph.schema import IMPORTANCE_BUCKET_SPAN, IMPORTANCE_WEIGHT, Insight, InsightCategory


def test_priority_weight_none_is_always_valid_regardless_of_importance():
    # Every insight the Reasoning Layer forms today -- must stay unaffected.
    Insight.create(InsightCategory.KNOWLEDGE_GAP, "gap", importance="high", priority_weight=None)
    Insight.create(InsightCategory.KNOWLEDGE_GAP, "gap", importance=None, priority_weight=None)


def test_priority_weight_within_its_buckets_range_is_valid():
    base = IMPORTANCE_WEIGHT["medium"]
    half_span = IMPORTANCE_BUCKET_SPAN / 2
    for w in (base - half_span, base, base + half_span):
        Insight.create(InsightCategory.KNOWLEDGE_GAP, "gap", importance="medium", priority_weight=w)


def test_priority_weight_outside_its_bucket_raises():
    base = IMPORTANCE_WEIGHT["medium"]
    half_span = IMPORTANCE_BUCKET_SPAN / 2
    with pytest.raises(ValueError, match="outside the valid range"):
        Insight.create(InsightCategory.KNOWLEDGE_GAP, "gap", importance="medium",
                        priority_weight=base + half_span + 0.01)


def test_priority_weight_belonging_to_a_different_bucket_raises():
    # The actual failure mode this guards against: a "low"-labeled insight
    # carrying a "high"-range weight would silently outrank a genuine
    # "medium" or "high" insight -- exactly what priority_weight exists to
    # prevent.
    with pytest.raises(ValueError, match="outside the valid range"):
        Insight.create(InsightCategory.KNOWLEDGE_GAP, "gap", importance="low",
                        priority_weight=IMPORTANCE_WEIGHT["high"])


def test_priority_weight_with_unknown_importance_string_is_not_checked():
    # importance not in IMPORTANCE_WEIGHT (malformed/legacy value) -- not
    # this validator's concern; it only checks CONSISTENCY between the two
    # fields when both are meaningful, never invents a bucket to check against.
    Insight.create(InsightCategory.KNOWLEDGE_GAP, "gap", importance="extremely-high", priority_weight=99.0)
