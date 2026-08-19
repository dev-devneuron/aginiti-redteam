"""Experiment 1 -- does gap_priority/hypothesis_priority actually change what
the planner does, and does that change help under a tight budget?

Claim under test (docs/EVIDENCE_AND_EVALUATION.md, "Adaptive planning" /
"Knowledge gaps"): a hypothesis- and gap-aware planner resolves more of the
operators that matter to open questions, within a fixed budget, than the
same planner with those terms removed.

Zero live cost, fully deterministic and reproducible: this is a controlled
synthetic experiment over AginitiPlanner.rank() itself (a pure function of
graph state), not a live campaign against a real or mock LLM target. That's
deliberate -- it isolates the PLANNING decision from target stochasticity
and judge noise, which a live run cannot do cleanly, and it costs zero
tokens, so it can run at a sample size (300 random synthetic worlds) no live
experiment in this project could afford.

Design, per trial (one random seed):
  - 20 operators, each with a unique CONFIRMED-only effect (weight=1), an
    edge from "start" that never leads toward the mission's (unreachable)
    target -- this neutralizes business_impact and path_progress for every
    operator, so only information_gain (identical for all unresolved
    operators, since weights match) and gap_priority/hypothesis_priority
    can differentiate ranking.
  - 6 operators are tagged by a KNOWLEDGE_GAP insight (random importance).
  - 6 DIFFERENT operators are each the sole experiment of an OPEN
    Hypothesis targeting that operator's own claim key.
  - 8 operators are plain (no gap/hypothesis link) -- an implicit control.
  - Operator insertion order is shuffled per trial, so the ABLATED
    planner's tie-broken-by-order behavior is a randomized baseline, not a
    fixed one the FULL planner could trivially beat by construction.

Two planners run against IDENTICAL, independently-instantiated copies of
this same world: FULL (real AginitiPlanner) and ABLATED (gap_priority and
hypothesis_priority hard-zeroed, everything else identical). Every chosen
operator "succeeds" deterministically (ssg.assert_claim(..., CONFIRMED)) --
this experiment is about PLANNING order, not about whether an operator
would succeed against a live target.

Budget is fixed at 10 (of 20 operators, 12 of them flagged) -- deliberately
LESS than the 12 flagged operators, so even the FULL planner is forced to
leave some flagged operators unresolved. This is what keeps the result from
being a trivial guaranteed-ceiling outcome: the question is whether FULL
resolves MORE of what matters within a tight budget, not whether it
resolves everything.
"""
from __future__ import annotations

import random
import statistics
import sys

sys.path.insert(0, ".")

from aginiti.graph.schema import ClaimStatus, InsightCategory, RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.planner.aginiti_planner import AginitiPlanner
from aginiti.stats import bootstrap_mean_ci, sign_test
from experiments.results_io import save_result

N_OPERATORS = 20
N_GAP_LINKED = 6
N_HYPOTHESIS_LINKED = 6
BUDGET = 10  # deliberately less than N_GAP_LINKED + N_HYPOTHESIS_LINKED (12) --
             # even the FULL planner must leave some flagged operators unresolved,
             # so this isn't a trivially-guaranteed ceiling result
N_TRIALS = 300


class AblatedPlanner(AginitiPlanner):
    """Identical to AginitiPlanner except the two understanding-driven
    terms are hard-zeroed -- the RQ1b-style ablation this experiment needs:
    a planner that still has information_gain/business_impact/path_progress
    but never reads insights or hypotheses."""

    def gap_priority(self, operator, ssg):
        return 0.0

    def hypothesis_priority(self, operator, ssg):
        return 0.0


def _build_ids(seed: int) -> tuple[list[str], set[str], set[str]]:
    rng = random.Random(seed)
    ids = [f"op_{i}" for i in range(N_OPERATORS)]
    rng.shuffle(ids)
    pool = ids[:]
    rng.shuffle(pool)
    gap_linked = set(pool[:N_GAP_LINKED])
    hyp_linked = set(pool[N_GAP_LINKED:N_GAP_LINKED + N_HYPOTHESIS_LINKED])
    return ids, gap_linked, hyp_linked


def _build_library(ids: list[str]) -> OperatorLibrary:
    ops = [
        Operator(
            id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
            effects_success=(ClaimEffect(f"{op_id}_done", ClaimStatus.CONFIRMED, weight=1),),
            effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
            graph_edge=("start", f"node_{op_id}"),
        )
        for op_id in ids
    ]
    return OperatorLibrary(ops)


def _seed_world(ssg: SecurityStateGraph, gap_linked: set[str], hyp_linked: set[str], seed: int) -> None:
    rng = random.Random(seed)
    for op_id in gap_linked:
        importance = rng.choice(["low", "medium", "high"])
        ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, f"unknown about {op_id}",
                            importance=importance, related_probe_id=op_id)
    for op_id in hyp_linked:
        ssg.form_hypothesis(f"hypothesis about {op_id}", f"{op_id}_done", ClaimStatus.CONFIRMED,
                             experiments=(op_id,), prior_confidence=0.5)


def _mission() -> Mission:
    return Mission(goal="unreachable by design", success_criteria=("unreachable_target",),
                    budget=BUDGET, risk_threshold=RiskTier.LOW)


def _run_one(planner: AginitiPlanner, library: OperatorLibrary, ssg: SecurityStateGraph) -> list[str]:
    """Greedy simulation: repeatedly rank, execute the top candidate by
    deterministically asserting its CONFIRMED effect, until BUDGET steps or
    no eligible candidate remains. Returns the ordered list of operator ids
    chosen."""
    mission = _mission()
    executed: list[str] = []
    for step in range(BUDGET):
        ranked = planner.rank(library, ssg, mission, prompts_used=step,
                               executed_ids=frozenset(executed))
        if not ranked:
            break
        chosen = ranked[0].operator
        effect = chosen.effects_success[0]
        ssg.assert_claim(effect.key, "true", effect.status)
        executed.append(chosen.id)
    return executed


def run_trial(seed: int) -> dict:
    ids, gap_linked, hyp_linked = _build_ids(seed)

    full_library, ablated_library = _build_library(ids), _build_library(ids)
    full_ssg, ablated_ssg = SecurityStateGraph(), SecurityStateGraph()
    _seed_world(full_ssg, gap_linked, hyp_linked, seed)
    _seed_world(ablated_ssg, gap_linked, hyp_linked, seed)

    full_order = _run_one(AginitiPlanner(), full_library, full_ssg)
    ablated_order = _run_one(AblatedPlanner(), ablated_library, ablated_ssg)

    assert len(full_order) == len(ablated_order) == BUDGET, "both planners must exhaust the fixed budget"

    def _frac_resolved(order: list[str], flagged: set[str]) -> float:
        return len(flagged & set(order)) / len(flagged)

    def _mean_step_index(order: list[str], flagged: set[str]) -> float | None:
        indices = [order.index(op_id) for op_id in flagged if op_id in order]
        return statistics.mean(indices) if indices else None

    return {
        "seed": seed,
        "full_gap_frac_resolved": _frac_resolved(full_order, gap_linked),
        "ablated_gap_frac_resolved": _frac_resolved(ablated_order, gap_linked),
        "full_hyp_frac_resolved": _frac_resolved(full_order, hyp_linked),
        "ablated_hyp_frac_resolved": _frac_resolved(ablated_order, hyp_linked),
        "full_total_resolved": len(full_order),
        "ablated_total_resolved": len(ablated_order),
        "full_gap_mean_step": _mean_step_index(full_order, gap_linked),
        "ablated_gap_mean_step": _mean_step_index(ablated_order, gap_linked),
        "full_hyp_mean_step": _mean_step_index(full_order, hyp_linked),
        "ablated_hyp_mean_step": _mean_step_index(ablated_order, hyp_linked),
    }


def main() -> None:
    trials = [run_trial(seed) for seed in range(N_TRIALS)]

    full_gap = [t["full_gap_frac_resolved"] for t in trials]
    ablated_gap = [t["ablated_gap_frac_resolved"] for t in trials]
    full_hyp = [t["full_hyp_frac_resolved"] for t in trials]
    ablated_hyp = [t["ablated_hyp_frac_resolved"] for t in trials]

    gap_sign = sign_test(full_gap, ablated_gap)
    hyp_sign = sign_test(full_hyp, ablated_hyp)

    gap_diffs = [f - a for f, a in zip(full_gap, ablated_gap)]
    hyp_diffs = [f - a for f, a in zip(full_hyp, ablated_hyp)]
    gap_diff_ci = bootstrap_mean_ci(gap_diffs)
    hyp_diff_ci = bootstrap_mean_ci(hyp_diffs)

    total_resolved_equal = all(t["full_total_resolved"] == t["ablated_total_resolved"] for t in trials)

    print(f"=== Experiment 1: gap/hypothesis priority ablation, n={N_TRIALS} trials ===")
    print(f"Fraction of gap-linked operators resolved within budget={BUDGET}/{N_OPERATORS}:")
    print(f"  FULL    mean={statistics.mean(full_gap):.3f}")
    print(f"  ABLATED mean={statistics.mean(ablated_gap):.3f}")
    print(f"  paired diff (FULL - ABLATED): {gap_diff_ci}")
    print(f"  sign test: {gap_sign.interpret()}")
    print()
    print(f"Fraction of hypothesis-linked operators resolved within budget:")
    print(f"  FULL    mean={statistics.mean(full_hyp):.3f}")
    print(f"  ABLATED mean={statistics.mean(ablated_hyp):.3f}")
    print(f"  paired diff (FULL - ABLATED): {hyp_diff_ci}")
    print(f"  sign test: {hyp_sign.interpret()}")
    print()
    print(f"Sanity check -- total operators resolved identical every trial (no throughput cost): "
          f"{total_resolved_equal}")

    path = save_result("exp1_hypothesis_gap_priority_ablation", {
        "n_trials": N_TRIALS,
        "n_operators": N_OPERATORS,
        "n_gap_linked": N_GAP_LINKED,
        "n_hypothesis_linked": N_HYPOTHESIS_LINKED,
        "budget": BUDGET,
        "gap_frac_resolved": {"full_mean": statistics.mean(full_gap), "ablated_mean": statistics.mean(ablated_gap),
                               "paired_diff_ci": str(gap_diff_ci), "sign_test": gap_sign.interpret(),
                               "n_positive": gap_sign.n_positive, "n_negative": gap_sign.n_negative,
                               "n_ties": gap_sign.n_ties, "p_value": gap_sign.p_value},
        "hyp_frac_resolved": {"full_mean": statistics.mean(full_hyp), "ablated_mean": statistics.mean(ablated_hyp),
                               "paired_diff_ci": str(hyp_diff_ci), "sign_test": hyp_sign.interpret(),
                               "n_positive": hyp_sign.n_positive, "n_negative": hyp_sign.n_negative,
                               "n_ties": hyp_sign.n_ties, "p_value": hyp_sign.p_value},
        "total_resolved_always_equal": total_resolved_equal,
        "raw_trials": trials,
    })
    print(f"\nsaved to {path}")


if __name__ == "__main__":
    main()
