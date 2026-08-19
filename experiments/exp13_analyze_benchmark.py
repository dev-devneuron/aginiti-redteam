"""Analysis pass for experiments/exp13_cold_start_fix_benchmark.py's raw trial
JSONs. Structure is unchanged from exp12_analyze_benchmark.py (same
CONDITIONS/MISSIONS, same per-condition/per-mission summary and Fisher's-exact
comparison logic) because exp13 reuses exp12's exact 3 branching missions and
5-condition design unchanged -- the only things different about exp13 are
upstream, in how the campaign was RUN (aginiti/graph/priors.py's cold-start
target-context seeding, wired in via run_campaign's new `target_briefing`
param, plus the new Groq->Gemini automatic fallback in aginiti/llm_client.py),
not in how results are shaped or scored. That makes this file's numbers
directly comparable, mission-for-mission and condition-for-condition, against
exp12's own saved results -- in particular branching_chat_rag, where exp12
found AginitiPolicy losing to Random (40% vs 80%) and root-caused it to
move-1 utility ties that seed_target_priors was built to break.
"""
from __future__ import annotations

import os
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aginiti.core.logging_utils import load_json
from aginiti.core.stats import bootstrap_mean_ci, compare_to_aginiti
from results_io import save_result

# N_TRIALS imported (not hardcoded) so the "expected vs found" honesty check
# below stays correct even if the benchmark script's own trial count changes.
from exp13_cold_start_fix_benchmark import N_TRIALS  # noqa: E402

RUN_DIR = "runs_live_anythingllm_benchmark/exp13_bench_20260809"
CONDITIONS = ("aginiti", "greedy_info_gain", "bfs_only", "random", "static")
MISSIONS = ("single_step_comprehensive", "branching_chat_rag", "branching_automatic_rag")


def _load_trials(mission: str, condition: str) -> tuple[list[dict], int]:
    """Returns (completed_trials, n_incomplete_skipped). Uses the EXACT same
    completeness rule as the live harness's own resume check
    (experiments/exp11_live_anythingllm_planner_benchmark.py's
    _trial_is_complete: a record counts only if it carries a real `outcome`
    key). A trial file existing on disk is NOT sufficient -- an error record
    (workspace-create/config/campaign failure, written so the resumable
    harness knows to retry it) has no `outcome` key and must never be
    silently counted as a completed (failed) trial here, which would
    understate the true success rate and inflate n_trials with runs that
    never actually executed. The second return value makes any such skip
    visible to the caller instead of swallowing it, honest reporting for
    a still-in-progress or partially-erroring run."""
    completed = []
    n_incomplete = 0
    for fname in sorted(os.listdir(RUN_DIR)):
        if fname.startswith(f"{mission}__{condition}_trial") and fname.endswith(".json"):
            record = load_json(os.path.join(RUN_DIR, fname))
            if "outcome" in record:
                completed.append(record)
            else:
                n_incomplete += 1
    return completed, n_incomplete


def _findings(trials: list[dict]) -> set[str]:
    keys = set()
    for t in trials:
        for e in t.get("execution_log", []):
            for eff in e.get("confirmed_effects", []):
                if eff.get("status") == "confirmed":
                    keys.add(eff["key"])
    return keys


def _condition_summary(mission: str, condition: str) -> dict:
    trials, n_incomplete = _load_trials(mission, condition)
    n = len(trials)
    successes = [t for t in trials if t.get("outcome") == "SUCCESS"]
    n_success = len(successes)
    prompts_all = [t["prompts_used"] for t in trials]
    prompts_success = [t["prompts_used"] for t in successes]
    branching_widths = [
        d["candidates_considered"] for t in trials for d in t.get("decision_log", []) if d.get("step") == 1
    ]
    return {
        "mission": mission, "condition": condition, "n_trials": n,
        # Real trials found on disk (outcome present) vs the run's own
        # target -- lets a mid-run or partially-erroring analysis pass be
        # reported honestly instead of silently treated as final.
        "n_trials_expected": N_TRIALS,
        "n_incomplete_or_errored": n_incomplete,
        "successes": n_success,
        "success_rate": n_success / n if n else 0.0,
        "mean_prompts_used": statistics.mean(prompts_all) if prompts_all else None,
        "mean_prompts_to_success": statistics.mean(prompts_success) if prompts_success else None,
        "median_prompts_to_success": statistics.median(prompts_success) if prompts_success else None,
        "findings_discovered": sorted(_findings(trials)),
        "n_distinct_findings": len(_findings(trials)),
        "mean_step1_branching_width": statistics.mean(branching_widths) if branching_widths else None,
        "outcomes": [t.get("outcome") for t in trials],
        "prompts_used_all": prompts_all,
    }


def main():
    all_summaries = {}
    for mission in MISSIONS:
        all_summaries[mission] = {c: _condition_summary(mission, c) for c in CONDITIONS}

    total_expected = len(MISSIONS) * len(CONDITIONS) * N_TRIALS
    total_found = sum(all_summaries[m][c]["n_trials"] for m in MISSIONS for c in CONDITIONS)
    total_incomplete = sum(all_summaries[m][c]["n_incomplete_or_errored"] for m in MISSIONS for c in CONDITIONS)
    print(f"Run completeness: {total_found}/{total_expected} completed trials on disk "
          f"({total_incomplete} incomplete/errored record(s) excluded from every stat below).")
    if total_found < total_expected:
        print("NOTE: this run is not yet complete (or some cells are still missing trials) -- "
              "treat every rate/mean below as a snapshot, not a final result, until "
              f"{total_found}/{total_expected} reaches {total_expected}/{total_expected}.")

    print("\n=== Per-mission, per-condition results ===")
    print(f"{'mission':28s} {'condition':18s} {'n':>5s} {'succ':>4s} {'rate':>6s} "
          f"{'mean_p':>7s} {'median_p':>9s} {'findings':>9s} {'branch@1':>9s}")
    for mission in MISSIONS:
        for condition in CONDITIONS:
            s = all_summaries[mission][condition]
            n_display = f"{s['n_trials']}/{s['n_trials_expected']}"
            print(f"{mission:28s} {condition:18s} {n_display:>5s} {s['successes']:>4d} "
                  f"{s['success_rate']:>6.1%} "
                  f"{(s['mean_prompts_to_success'] or 0):>7.2f} "
                  f"{(s['median_prompts_to_success'] or 0):>9.2f} "
                  f"{s['n_distinct_findings']:>9d} "
                  f"{(s['mean_step1_branching_width'] or 0):>9.2f}"
                  + (f"  [{s['n_incomplete_or_errored']} errored/incomplete excluded]"
                     if s['n_incomplete_or_errored'] else ""))

    print("\n=== Statistical comparison: aginiti vs each baseline (Fisher's exact, success rate) ===")
    stat_comparisons = {}
    for mission in MISSIONS:
        stat_comparisons[mission] = {}
        a = all_summaries[mission]["aginiti"]
        for baseline in ("greedy_info_gain", "bfs_only", "random", "static"):
            b = all_summaries[mission][baseline]
            cmp = compare_to_aginiti(a["successes"], a["n_trials"], baseline, b["successes"], b["n_trials"])
            stat_comparisons[mission][baseline] = {
                "p_value": cmp.p_value, "n_total": cmp.n_total, "interpretation": cmp.interpret(),
            }
            print(f"{mission:28s} aginiti({a['successes']}/{a['n_trials']}) vs "
                  f"{baseline}({b['successes']}/{b['n_trials']}): {cmp.interpret()}")

    print("\n=== OVERALL (pooled across all 3 missions) ===")
    overall = {}
    for condition in CONDITIONS:
        n = sum(all_summaries[m][condition]["n_trials"] for m in MISSIONS)
        n_incomplete = sum(all_summaries[m][condition]["n_incomplete_or_errored"] for m in MISSIONS)
        succ = sum(all_summaries[m][condition]["successes"] for m in MISSIONS)
        all_prompts_success = []
        for m in MISSIONS:
            trials, _ = _load_trials(m, condition)
            all_prompts_success += [t["prompts_used"] for t in trials if t.get("outcome") == "SUCCESS"]
        overall[condition] = {
            "n_trials": n, "n_trials_expected": len(MISSIONS) * N_TRIALS, "n_incomplete_or_errored": n_incomplete,
            "successes": succ, "success_rate": succ / n if n else 0.0,
            "mean_prompts_to_success": statistics.mean(all_prompts_success) if all_prompts_success else None,
            "median_prompts_to_success": statistics.median(all_prompts_success) if all_prompts_success else None,
            "bootstrap_ci_prompts_to_success": (
                str(bootstrap_mean_ci(all_prompts_success)) if len(all_prompts_success) >= 2 else None
            ),
        }
        incomplete_note = f"  [{n_incomplete} errored/incomplete excluded]" if n_incomplete else ""
        print((f"{condition:18s} {succ}/{n} = {succ/n:.1%}{incomplete_note}" if n
               else f"{condition:18s} n=0{incomplete_note}"))

    overall_stat_comparisons = {}
    a = overall["aginiti"]
    for baseline in ("greedy_info_gain", "bfs_only", "random", "static"):
        b = overall[baseline]
        cmp = compare_to_aginiti(a["successes"], a["n_trials"], baseline, b["successes"], b["n_trials"])
        overall_stat_comparisons[baseline] = {
            "p_value": cmp.p_value, "n_total": cmp.n_total, "interpretation": cmp.interpret(),
        }
        print(f"OVERALL: aginiti({a['successes']}/{a['n_trials']}) vs {baseline}({b['successes']}/{b['n_trials']}): "
              f"{cmp.interpret()}")

    path = save_result("exp13_cold_start_fix_benchmark", {
        "run_dir": RUN_DIR,
        "conditions": list(CONDITIONS),
        "missions": list(MISSIONS),
        "run_completeness": {
            "n_trials_found": total_found, "n_trials_expected": total_expected,
            "n_incomplete_or_errored": total_incomplete, "is_complete": total_found >= total_expected,
        },
        "per_mission_per_condition": all_summaries,
        "per_mission_stat_comparisons": stat_comparisons,
        "overall_per_condition": overall,
        "overall_stat_comparisons": overall_stat_comparisons,
    })
    print(f"\nSaved: {path}")


if __name__ == "__main__":
    main()
