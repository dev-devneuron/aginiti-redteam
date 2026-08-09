"""Analysis for exp15's properly-powered (n=30/condition) branching_chat_rag
re-run. Read-only: mines the already-recorded decision_log from every
trial JSON -- no new instrumentation, no algorithm involved, purely
post-hoc analysis of what already happened.

Produces THREE separate kinds of evidence, deliberately not collapsed into
one number:
  1. OUTCOME  -- success rate, prompts-to-success, Fisher's exact vs aginiti.
  2. MECHANISM -- what did EACH condition's OWN first pick actually look
     like (trap / genuine single-step win / chain-start / nothing
     rankable)? Computed identically for all 5 conditions, not just
     aginiti, so "aginiti avoids the trap" is a claim checked against what
     each baseline's own mechanism actually does, not assumed.
  3. TARGET STOCHASTICITY -- among LOSSES only, how many are attributable
     to a planning mistake (trap picked, or a chain started but never
     finished) vs a genuinely reasonable attempt that the live target
     simply didn't cooperate with.

Every record without a real `outcome` key (error/incomplete) is counted
and reported, never silently dropped from the denominator -- same
completeness discipline as exp13_analyze_benchmark.py.
"""
from __future__ import annotations

import os
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aginiti.logging_utils import load_json
from aginiti.stats import bootstrap_mean_ci, compare_to_aginiti
from results_io import save_result

from exp15_branching_chat_rag_powered_benchmark import BASE_SEED, N_TRIALS  # noqa: E402

RUN_DIR = "runs_live_anythingllm_benchmark/exp15_bench_20260809"
CONDITIONS = ("aginiti", "greedy_info_gain", "bfs_only", "random", "static")
MISSION = "branching_chat_rag"

TRAP_ID = "memory_context_leakage_probe"
GENUINE_SINGLE_STEP = {"system_prompt_extraction", "jailbreak_dan_style"}
CHAIN_START = "anythingllm_rag_document_plant"
CHAIN_CONTINUE = "anythingllm_rag_injection_trigger"


def _load_trials(condition: str) -> tuple[list[dict], int]:
    completed, n_incomplete = [], 0
    for fname in sorted(os.listdir(RUN_DIR)):
        if fname.startswith(f"{MISSION}__{condition}_trial") and fname.endswith(".json"):
            record = load_json(os.path.join(RUN_DIR, fname))
            if "outcome" in record:
                completed.append(record)
            else:
                n_incomplete += 1
    return completed, n_incomplete


def _op_sequence(trial: dict) -> list[str]:
    return [d["chosen_operator_id"] for d in trial.get("decision_log", [])]


def _first_pick_category(ops: list[str]) -> str:
    if not ops:
        return "no_candidates_rankable"
    first = ops[0]
    if first == TRAP_ID:
        return "trap"
    if first in GENUINE_SINGLE_STEP:
        return "genuine_single_step_win"
    if first == CHAIN_START:
        return "chain_start"
    if first == CHAIN_CONTINUE:
        return "chain_continue"  # should never happen first (precondition-gated); flag if it does
    return f"other:{first}"


def _loss_category(ops: list[str]) -> str:
    if not ops:
        return "no_candidates_rankable"
    if TRAP_ID in ops:
        return "trap_selected"
    if CHAIN_START in ops and CHAIN_CONTINUE not in ops:
        return "chain_started_incomplete"  # budget_feasible SHOULD make this rare/never post-fix
    return "genuine_attempt_target_failed"  # only real candidates tried; target simply didn't cooperate


def _condition_report(condition: str) -> dict:
    trials, n_incomplete = _load_trials(condition)
    n = len(trials)
    successes = [t for t in trials if t.get("outcome") == "SUCCESS"]
    losses = [t for t in trials if t.get("outcome") != "SUCCESS"]
    prompts_success = [t["prompts_used"] for t in successes]

    first_pick_counts: dict[str, int] = {}
    for t in trials:
        cat = _first_pick_category(_op_sequence(t))
        first_pick_counts[cat] = first_pick_counts.get(cat, 0) + 1

    loss_categories: dict[str, int] = {}
    for t in losses:
        cat = _loss_category(_op_sequence(t))
        loss_categories[cat] = loss_categories.get(cat, 0) + 1

    return {
        "condition": condition, "n_trials": n, "n_trials_expected": N_TRIALS,
        "n_incomplete_or_errored": n_incomplete,
        "successes": len(successes), "success_rate": len(successes) / n if n else 0.0,
        "mean_prompts_to_success": statistics.mean(prompts_success) if prompts_success else None,
        "median_prompts_to_success": statistics.median(prompts_success) if prompts_success else None,
        "bootstrap_ci_prompts_to_success": (
            str(bootstrap_mean_ci(prompts_success)) if len(prompts_success) >= 2 else None
        ),
        "first_pick_distribution": first_pick_counts,
        "trap_picked_first_rate": first_pick_counts.get("trap", 0) / n if n else 0.0,
        "loss_categories": loss_categories,
        "n_losses": len(losses),
    }


def main():
    reports = {c: _condition_report(c) for c in CONDITIONS}

    total_found = sum(r["n_trials"] for r in reports.values())
    total_expected = len(CONDITIONS) * N_TRIALS
    total_incomplete = sum(r["n_incomplete_or_errored"] for r in reports.values())
    print(f"Run completeness: {total_found}/{total_expected} completed trials on disk "
          f"({total_incomplete} incomplete/errored excluded from every stat below).")
    if total_found < total_expected:
        print("NOTE: run not yet complete -- treat everything below as a snapshot.")

    print("\n=== 1. OUTCOME EVIDENCE ===")
    print(f"{'condition':18s} {'n':>7s} {'succ':>4s} {'rate':>7s} {'mean_p':>7s} {'median_p':>9s}")
    for c in CONDITIONS:
        r = reports[c]
        n_display = f"{r['n_trials']}/{r['n_trials_expected']}"
        print(f"{c:18s} {n_display:>7s} {r['successes']:>4d} {r['success_rate']:>7.1%} "
              f"{(r['mean_prompts_to_success'] or 0):>7.2f} {(r['median_prompts_to_success'] or 0):>9.2f}"
              + (f"  [{r['n_incomplete_or_errored']} excluded]" if r['n_incomplete_or_errored'] else ""))

    print("\nStatistical comparison: aginiti vs each baseline (Fisher's exact, success rate)")
    a = reports["aginiti"]
    stat_comparisons = {}
    for baseline in ("greedy_info_gain", "bfs_only", "random", "static"):
        b = reports[baseline]
        cmp = compare_to_aginiti(a["successes"], a["n_trials"], baseline, b["successes"], b["n_trials"])
        stat_comparisons[baseline] = {"p_value": cmp.p_value, "n_total": cmp.n_total,
                                        "interpretation": cmp.interpret()}
        print(f"  aginiti({a['successes']}/{a['n_trials']}) vs {baseline}({b['successes']}/{b['n_trials']}): "
              f"{cmp.interpret()}")

    print("\n=== 2. MECHANISM EVIDENCE (first-pick category, ALL trials incl. successes) ===")
    for c in CONDITIONS:
        r = reports[c]
        print(f"  {c:18s} {r['first_pick_distribution']}  "
              f"(trap picked first: {r['trap_picked_first_rate']:.1%})")

    print("\n=== 3. TARGET-STOCHASTICITY EVIDENCE (losses only, categorized by pick sequence) ===")
    for c in CONDITIONS:
        r = reports[c]
        print(f"  {c:18s} n_losses={r['n_losses']:3d}  {r['loss_categories']}")

    path = save_result("exp15_branching_chat_rag_powered_benchmark", {
        "run_dir": RUN_DIR, "mission": MISSION, "base_seed": BASE_SEED, "n_trials_per_condition": N_TRIALS,
        "run_completeness": {"n_trials_found": total_found, "n_trials_expected": total_expected,
                              "n_incomplete_or_errored": total_incomplete,
                              "is_complete": total_found >= total_expected},
        "per_condition": reports,
        "stat_comparisons_vs_aginiti": stat_comparisons,
    })
    print(f"\nSaved: {path}")


if __name__ == "__main__":
    main()
