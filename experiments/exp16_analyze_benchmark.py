"""Analysis for exp16 -- the user-requested honest test of whether Aginiti
beats GreedyInfoGain/Random/Static/BFSOnly on a genuinely branching,
budget=1 mission. Produces the three things asked for explicitly, kept
separate rather than collapsed into one number:
  1. OUTCOME  -- success rate, prompts-to-success, Fisher's exact vs Aginiti.
  2. MECHANISM -- what did the single (budget=1) pick actually look like:
     a genuine win, the known trap, or the un-completable chain-start?
  3. USEFUL VS WASTED STEPS -- since budget=1 means exactly one step per
     trial, "wasted" here means the step spent on an operator that could
     not possibly have won (trap, or the chain-start, which needs a
     2nd operator budget=1 structurally forbids) -- a strictly stronger,
     more mechanical classification than "the trial happened to lose."

Same completeness discipline as exp13/15's analyzers: only records with a
real `outcome` key count; anything else is reported, never silently
dropped.
"""
from __future__ import annotations

import os
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aginiti.core.logging_utils import load_json
from aginiti.core.stats import bootstrap_mean_ci, compare_to_aginiti
from results_io import save_result

from exp16_tight_budget_validation import BASE_SEED, N_TRIALS  # noqa: E402

RUN_DIR = "experiments/results/runs_live_anythingllm_benchmark/exp16_bench_20260809"
CONDITIONS = ("aginiti", "greedy_info_gain", "bfs_only", "random", "static", "bayesian")
NON_BFS_BASELINES = ("greedy_info_gain", "random", "static")
MISSION = "branching_chat_rag"

TRAP_ID = "memory_context_leakage_probe"
GENUINE_SINGLE_STEP = {"system_prompt_extraction", "jailbreak_dan_style"}
CHAIN_START = "anythingllm_rag_document_plant"


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


def _first_pick(trial: dict) -> str | None:
    dl = trial.get("decision_log", [])
    return dl[0]["chosen_operator_id"] if dl else None


def _pick_category(op_id: str | None) -> str:
    if op_id is None:
        return "no_candidates_rankable"
    if op_id == TRAP_ID:
        return "trap"
    if op_id in GENUINE_SINGLE_STEP:
        return "genuine_win"
    if op_id == CHAIN_START:
        return "chain_start_doomed_at_budget_1"
    return f"other:{op_id}"


def _is_wasted_step(op_id: str | None) -> bool:
    """A step is WASTED if it was spent on something that could not
    possibly have won at budget=1, regardless of what the live target
    actually did: the trap (established, real, always-defended) or the
    chain-start (structurally needs a 2nd operator budget=1 forbids).
    A genuine-win pick is never counted wasted here even if that specific
    trial happened to lose -- that outcome is target-side variance, the
    thing this metric is explicitly built to separate out from planning
    quality."""
    return op_id in (TRAP_ID, CHAIN_START)


def _condition_report(condition: str) -> dict:
    trials, n_incomplete = _load_trials(condition)
    n = len(trials)
    successes = [t for t in trials if t.get("outcome") == "SUCCESS"]
    prompts_success = [t["prompts_used"] for t in successes]

    pick_categories: dict[str, int] = {}
    wasted = 0
    useful = 0
    for t in trials:
        op = _first_pick(t)
        cat = _pick_category(op)
        pick_categories[cat] = pick_categories.get(cat, 0) + 1
        if _is_wasted_step(op):
            wasted += 1
        elif op is not None:
            useful += 1

    # Mechanism-vs-target-stochasticity split, ONLY among genuine_win picks:
    # of the trials that picked a real win, how many still lost? That
    # residual loss rate is the actual target-side variance component,
    # isolated from planning quality entirely.
    genuine_win_trials = [t for t in trials if _first_pick(t) in GENUINE_SINGLE_STEP]
    genuine_win_successes = sum(1 for t in genuine_win_trials if t.get("outcome") == "SUCCESS")

    return {
        "condition": condition, "n_trials": n, "n_trials_expected": N_TRIALS,
        "n_incomplete_or_errored": n_incomplete,
        "successes": len(successes), "success_rate": len(successes) / n if n else 0.0,
        "mean_prompts_to_success": statistics.mean(prompts_success) if prompts_success else None,
        "bootstrap_ci_prompts_to_success": (
            str(bootstrap_mean_ci(prompts_success)) if len(prompts_success) >= 2 else None
        ),
        "pick_categories": pick_categories,
        "useful_steps": useful, "wasted_steps": wasted,
        "wasted_step_rate": wasted / n if n else 0.0,
        "genuine_win_trials": len(genuine_win_trials),
        "genuine_win_successes": genuine_win_successes,
        "genuine_win_success_rate": (genuine_win_successes / len(genuine_win_trials)
                                      if genuine_win_trials else None),
    }


def main():
    reports = {c: _condition_report(c) for c in CONDITIONS}

    total_found = sum(r["n_trials"] for r in reports.values())
    total_expected = len(CONDITIONS) * N_TRIALS
    total_incomplete = sum(r["n_incomplete_or_errored"] for r in reports.values())
    print(f"Run completeness: {total_found}/{total_expected} completed trials on disk "
          f"({total_incomplete} incomplete/errored excluded).")
    if total_found < total_expected:
        print("NOTE: run not yet complete -- treat everything below as a snapshot.")

    print("\n=== 1. OUTCOME EVIDENCE ===")
    print(f"{'condition':18s} {'n':>7s} {'succ':>4s} {'rate':>7s} {'mean_p':>7s}")
    for c in CONDITIONS:
        r = reports[c]
        n_display = f"{r['n_trials']}/{r['n_trials_expected']}"
        print(f"{c:18s} {n_display:>7s} {r['successes']:>4d} {r['success_rate']:>7.1%} "
              f"{(r['mean_prompts_to_success'] or 0):>7.2f}")

    print("\nStatistical comparison: Aginiti vs each NON-BFS baseline (Fisher's exact, success rate)")
    a = reports["aginiti"]
    stat_comparisons = {}
    for baseline in NON_BFS_BASELINES:
        b = reports[baseline]
        cmp = compare_to_aginiti(a["successes"], a["n_trials"], baseline, b["successes"], b["n_trials"])
        stat_comparisons[baseline] = {"p_value": cmp.p_value, "n_total": cmp.n_total,
                                        "interpretation": cmp.interpret()}
        print(f"  aginiti({a['successes']}/{a['n_trials']}) vs {baseline}({b['successes']}/{b['n_trials']}): "
              f"{cmp.interpret()}")

    # Secondary, explicitly-requested comparison: does `bayesian` add real value over aginiti?
    bay = reports["bayesian"]
    bay_cmp = compare_to_aginiti(a["successes"], a["n_trials"], "bayesian", bay["successes"], bay["n_trials"])
    print(f"\n  aginiti({a['successes']}/{a['n_trials']}) vs bayesian({bay['successes']}/{bay['n_trials']}): "
          f"{bay_cmp.interpret()}")
    stat_comparisons["bayesian"] = {"p_value": bay_cmp.p_value, "n_total": bay_cmp.n_total,
                                      "interpretation": bay_cmp.interpret()}

    print("\n=== 2. MECHANISM EVIDENCE (single budget=1 pick, all trials) ===")
    for c in CONDITIONS:
        r = reports[c]
        print(f"  {c:18s} {r['pick_categories']}")

    print("\n=== 3. USEFUL VS WASTED STEPS ===")
    print(f"{'condition':18s} {'useful':>7s} {'wasted':>7s} {'wasted_rate':>12s}")
    for c in CONDITIONS:
        r = reports[c]
        print(f"  {c:18s} {r['useful_steps']:>7d} {r['wasted_steps']:>7d} {r['wasted_step_rate']:>11.1%}")

    print("\n=== 4. MECHANISM vs TARGET-SIDE VARIANCE (residual loss rate GIVEN a genuine-win pick) ===")
    print("(isolates: among trials that picked a REAL win, how often did the target itself still fail it?)")
    for c in CONDITIONS:
        r = reports[c]
        gw_rate = r["genuine_win_success_rate"]
        gw_display = f"{gw_rate:.1%}" if gw_rate is not None else "n/a (never picked a genuine win)"
        print(f"  {c:18s} genuine-win picks: {r['genuine_win_trials']:3d}, "
              f"succeeded when picked: {gw_display}")

    path = save_result("exp16_tight_budget_validation", {
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
