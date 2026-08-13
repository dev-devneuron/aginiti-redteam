"""
Population-level MIA benchmark metrics — AUC-ROC, TPR@fixed-FPR, and
Accuracy@fixed-FPR — computed from raw (score, true_label) pairs, matching
the methodology of "Riddle Me This! Stealthy Membership Inference for RAG"
(Naseh, Peng, Suri, Chaudhari, Oprea, Houmansadr — ACM CCS 2025,
arXiv:2502.00306v2) Table 2.

**This is a different exercise than `InterrogationAttack.execute_black_box`
's per-document threshold decision** (calibrate a threshold once from a
small non-member reference set, then confirm/deny each candidate against
it). These metrics need every document's raw score plus its TRUE label,
across a large-enough labeled set, and derive their own operating-point
thresholds directly from that same set's ROC curve — no separate
calibration split. See `InterrogationAttack.score_documents` (the
threshold-free scoring entry point this module is meant to consume) and
`aginiti/attacks/mia/README.md`'s "Benchmarking metrics" section.

Deliberately hand-rolled, not scikit-learn — this is well-defined,
self-contained math (a monotonic threshold sweep + trapezoidal
integration), not enough to justify a new dependency for the whole library.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _roc_points(scored: list[tuple[float, bool]]) -> list[tuple[float, float, float]]:
    """
    scored: list of (score, is_member) pairs.

    Returns points as (threshold, fpr, tpr), sorted by ascending fpr (which
    is exactly descending score/threshold — sweeping the decision threshold
    down from +inf classifies one more document "member" at a time, so both
    fpr and tpr are non-decreasing as this list is built). Starts with a
    synthetic (+inf, 0.0, 0.0) point (nothing classified positive yet).

    Tied scores are grouped and emitted as a single point — otherwise the
    same threshold value could be reported at two different (fpr, tpr)
    points depending on which tied document happened to be "processed
    first," which isn't a real operating point.
    """
    n_pos = sum(1 for _, is_member in scored if is_member)
    n_neg = len(scored) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError(
            f"Need at least one true member AND one true non-member to "
            f"compute an ROC curve (got {n_pos} members, {n_neg} non-members). "
            f"This is exactly the population-scale requirement described in "
            f"aginiti/attacks/mia/README.md's 'Benchmarking metrics' section."
        )

    ordered = sorted(scored, key=lambda pair: -pair[0])
    points: list[tuple[float, float, float]] = [(float("inf"), 0.0, 0.0)]
    tp = fp = 0
    i = 0
    while i < len(ordered):
        score = ordered[i][0]
        j = i
        while j < len(ordered) and ordered[j][0] == score:
            if ordered[j][1]:
                tp += 1
            else:
                fp += 1
            j += 1
        points.append((score, fp / n_neg, tp / n_pos))
        i = j
    return points


def _auc_from_points(points: list[tuple[float, float, float]]) -> float:
    """Trapezoidal integration of the ROC curve. points must be ascending-fpr."""
    auc = 0.0
    for (_, fpr0, tpr0), (_, fpr1, tpr1) in zip(points, points[1:]):
        auc += (fpr1 - fpr0) * (tpr0 + tpr1) / 2.0
    return auc


def _tpr_at_fpr(points: list[tuple[float, float, float]], target_fpr: float) -> float:
    """Linearly interpolates TPR at the given FPR along the ROC curve."""
    for (_, fpr0, tpr0), (_, fpr1, tpr1) in zip(points, points[1:]):
        if fpr0 <= target_fpr <= fpr1:
            if fpr1 == fpr0:
                return max(tpr0, tpr1)
            frac = (target_fpr - fpr0) / (fpr1 - fpr0)
            return tpr0 + frac * (tpr1 - tpr0)
    return points[-1][2]


def _threshold_for_fpr(points: list[tuple[float, float, float]], target_fpr: float) -> float:
    """
    Score threshold at the first point (ascending fpr) whose fpr >=
    target_fpr — the paper's own "accuracy at the threshold set by FPR=X%"
    methodology: the most conservative (highest) threshold that still
    reaches at least the target false-positive rate on this dataset.
    """
    for threshold, fpr, _tpr in points:
        if fpr >= target_fpr:
            return threshold
    return points[-1][0]


def _accuracy_at_threshold(pairs: list[tuple[float, bool]], threshold: float) -> float:
    if not pairs:
        return 0.0
    correct = sum(1 for score, is_member in pairs if (score >= threshold) == is_member)
    return correct / len(pairs)


def compute_mia_benchmark_metrics(scored_documents: list[dict]) -> dict:
    """
    Computes the paper's Table 2 metrics from a labeled, scored document set.

    Parameters
    ----------
    scored_documents : list[dict]
        Each ``{"id": str, "score": float, "is_member": bool}`` — ``score``
        is `InterrogationAttack.score_documents`'s raw Stage C output;
        ``is_member`` is the CALLER's ground-truth label (which dataset the
        document actually came from — this module has no way to know that
        itself).

    Returns
    -------
    dict
        ``{"n_members", "n_non_members", "fpr_granularity", "auc_roc",
        "tpr_at_fpr_0_5pct", "tpr_at_fpr_1pct", "tpr_at_fpr_5pct",
        "threshold_at_fpr10", "accuracy_at_fpr10"}``. ``fpr_granularity``
        (= 1 / n_non_members) is the finest FPR step this dataset can
        actually resolve — a WARNING is logged for any TPR@X%FPR figure
        below that granularity, since it isn't a reliably-measured point on
        this dataset, just the nearest achievable one (see
        aginiti/attacks/mia/README.md's "Benchmarking metrics" section for
        why document count, not just probe count, determines whether these
        figures are meaningful at all).
    """
    pairs = [(float(d["score"]), bool(d["is_member"])) for d in scored_documents]
    n_pos = sum(1 for _, m in pairs if m)
    n_neg = len(pairs) - n_pos
    points = _roc_points(pairs)

    fpr_granularity = 1.0 / n_neg if n_neg else 1.0
    for label, target_fpr in (
        ("TPR@0.5%FPR", 0.005), ("TPR@1%FPR", 0.01), ("TPR@5%FPR", 0.05),
    ):
        if target_fpr < fpr_granularity:
            logger.warning(
                "[MIA METRICS] %s requested but this dataset's %d non-member "
                "documents only resolve FPR in steps of %.2f%% — this figure "
                "is the nearest achievable point, not a reliable estimate at "
                "the requested FPR. More non-member documents are needed for "
                "a trustworthy reading (see aginiti/attacks/mia/README.md's "
                "'Benchmarking metrics' section).",
                label, n_neg, fpr_granularity * 100,
            )

    threshold_10 = _threshold_for_fpr(points, 0.10)
    return {
        "n_members": n_pos,
        "n_non_members": n_neg,
        "fpr_granularity": fpr_granularity,
        "auc_roc": _auc_from_points(points),
        "tpr_at_fpr_0_5pct": _tpr_at_fpr(points, 0.005),
        "tpr_at_fpr_1pct": _tpr_at_fpr(points, 0.01),
        "tpr_at_fpr_5pct": _tpr_at_fpr(points, 0.05),
        "threshold_at_fpr10": threshold_10,
        "accuracy_at_fpr10": _accuracy_at_threshold(pairs, threshold_10),
    }
