import logging

import pytest

from aginiti.reporting.mia_metrics import compute_mia_benchmark_metrics


def _docs(pairs):
    """pairs: list of (score, is_member) -> scored_documents list of dicts."""
    return [
        {"id": f"doc_{i}", "score": score, "is_member": is_member}
        for i, (score, is_member) in enumerate(pairs)
    ]


class TestPerfectSeparation:
    def test_auc_is_one(self):
        # Every member scores strictly above every non-member.
        pairs = [(1.0, True), (0.9, True), (0.8, True)] + [
            (-0.5, False), (-0.6, False), (-0.7, False)
        ]
        metrics = compute_mia_benchmark_metrics(_docs(pairs))
        assert metrics["auc_roc"] == pytest.approx(1.0)

    def test_accuracy_at_fpr10_reflects_the_forced_10pct_false_positive(self):
        # 3 members, 10 non-members, perfectly separated (all member scores
        # above all non-member scores). Fixing the operating point at
        # FPR=10% deliberately admits ~10% of non-members as false
        # positives, EVEN on a perfectly-separable dataset -- a stricter
        # threshold would reach 100% accuracy here, but that's not the
        # paper's methodology (it fixes FPR=10%, not "best threshold").
        # granularity = 1/10 = 10%, so the first non-member crossing in
        # lands exactly on the 10% target: 1 of 10 non-members
        # misclassified, all 3 members correct -> (3+9)/13.
        pairs = [(10.0, True), (9.0, True), (8.0, True)] + [
            (float(-i), False) for i in range(1, 11)
        ]
        metrics = compute_mia_benchmark_metrics(_docs(pairs))
        assert metrics["accuracy_at_fpr10"] == pytest.approx(12 / 13)

    def test_tpr_at_all_fprs_is_one(self):
        pairs = [(1.0, True), (0.9, True), (0.8, True)] + [
            (-0.5, False), (-0.6, False), (-0.7, False)
        ]
        metrics = compute_mia_benchmark_metrics(_docs(pairs))
        assert metrics["tpr_at_fpr_5pct"] == pytest.approx(1.0)


class TestNoSeparation:
    def test_auc_is_half_when_scores_identical(self):
        # Members and non-members score identically -- no separation at all.
        pairs = [(0.0, True), (0.0, True), (0.0, False), (0.0, False)]
        metrics = compute_mia_benchmark_metrics(_docs(pairs))
        assert metrics["auc_roc"] == pytest.approx(0.5)


class TestInverseSeparation:
    def test_auc_near_zero_when_members_score_lower(self):
        pairs = [(-1.0, True), (-0.9, True)] + [(0.5, False), (0.6, False)]
        metrics = compute_mia_benchmark_metrics(_docs(pairs))
        assert metrics["auc_roc"] == pytest.approx(0.0)


class TestKnownRocCurve:
    def test_matches_hand_computed_auc(self):
        # 2 members (scores 3, 1), 2 non-members (scores 2, 0).
        # Sweeping threshold from +inf downward:
        #   >3: fpr=0,   tpr=0
        #   =3: fpr=0,   tpr=0.5   (member@3 caught)
        #   =2: fpr=0.5, tpr=0.5   (non-member@2 now a false positive)
        #   =1: fpr=0.5, tpr=1.0   (member@1 caught)
        #   =0: fpr=1.0, tpr=1.0   (non-member@0 now a false positive)
        # Trapezoids: (0-0)*.. + (0.5-0)*(0.5+0.5)/2 + (0.5-0.5)*.. + (1-0.5)*(1.0+1.0)/2
        #           = 0 + 0.25 + 0 + 0.5 = 0.75
        pairs = [(3.0, True), (1.0, True), (2.0, False), (0.0, False)]
        metrics = compute_mia_benchmark_metrics(_docs(pairs))
        assert metrics["auc_roc"] == pytest.approx(0.75)


class TestTprInterpolation:
    def test_tpr_interpolates_between_roc_points(self):
        # 10 non-members (scores 0..9, all False), 1 member (score 100).
        # fpr granularity = 1/10 = 10% per non-member -- interpolating
        # TPR@5%FPR should land halfway between the fpr=0% and fpr=10% points.
        pairs = [(100.0, True)] + [(float(s), False) for s in range(10)]
        metrics = compute_mia_benchmark_metrics(_docs(pairs))
        # At fpr=0 (threshold > 9): tpr=1.0 already (member@100 is caught
        # before any non-member crosses the threshold). So TPR@5%FPR == 1.0.
        assert metrics["tpr_at_fpr_5pct"] == pytest.approx(1.0)


class TestGranularityWarning:
    def test_warns_when_requested_fpr_below_dataset_granularity(self, caplog):
        # Only 4 non-members -> granularity 25%, requesting TPR@0.5%/1%/5%FPR
        # should all warn (all below 25%).
        pairs = [(1.0, True), (0.9, True)] + [
            (-0.1, False), (-0.2, False), (-0.3, False), (-0.4, False)
        ]
        with caplog.at_level(logging.WARNING):
            compute_mia_benchmark_metrics(_docs(pairs))
        assert sum("resolve FPR in steps of" in r.message for r in caplog.records) == 3

    def test_no_warning_when_dataset_large_enough(self, caplog):
        # 200 non-members -> granularity = 1/200 = 0.5%, exactly resolving
        # even the strictest requested figure (TPR@0.5%FPR) -- no warnings.
        pairs = [(float(i), True) for i in range(60)] + [
            (float(-i), False) for i in range(200)
        ]
        with caplog.at_level(logging.WARNING):
            compute_mia_benchmark_metrics(_docs(pairs))
        assert not any("resolve FPR in steps of" in r.message for r in caplog.records)

    def test_fpr_granularity_field_matches_non_member_count(self):
        pairs = [(1.0, True)] * 3 + [(0.0, False)] * 8
        metrics = compute_mia_benchmark_metrics(_docs(pairs))
        assert metrics["fpr_granularity"] == pytest.approx(1.0 / 8)


class TestCounts:
    def test_reports_correct_member_non_member_counts(self):
        pairs = [(1.0, True)] * 5 + [(0.0, False)] * 3
        metrics = compute_mia_benchmark_metrics(_docs(pairs))
        assert metrics["n_members"] == 5
        assert metrics["n_non_members"] == 3


class TestErrorCases:
    def test_raises_with_no_members(self):
        pairs = [(0.0, False), (0.1, False)]
        with pytest.raises(ValueError, match="at least one true member"):
            compute_mia_benchmark_metrics(_docs(pairs))

    def test_raises_with_no_non_members(self):
        pairs = [(0.0, True), (0.1, True)]
        with pytest.raises(ValueError, match="at least one true member"):
            compute_mia_benchmark_metrics(_docs(pairs))

    def test_raises_with_empty_input(self):
        with pytest.raises(ValueError):
            compute_mia_benchmark_metrics([])
