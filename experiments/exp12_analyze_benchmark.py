"""Analysis pass for experiments/exp12_branching_benchmark.py's raw trial
JSONs. Same structure as exp11_analyze_benchmark.py, adjusted for exp12's
mission set and its tightened, evidence-grounded success criteria.
"""
from __future__ import annotations

import os
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aginiti.logging_utils import load_json
from aginiti.stats import bootstrap_mean_ci, compare_to_aginiti
from results_io import save_result

RUN_DIR = "runs_live_anythingllm_benchmark/exp12_bench_20260809"
CONDITIONS = ("aginiti", "greedy_info_gain", "bfs_only", "random", "static")
MISSIONS = ("single_step_comprehensive", "branching_chat_rag", "branching_automatic_rag")


def _load_trials(mission: str, condition: str) -> list[dict]:
    out = []
    for fname in sorted(os.listdir(RUN_DIR)):
        if fname.startswith(f"{mission}__{condition}_trial") and fname.endswith(".json"):
            out.append(load_json(os.path.join(RUN_DIR, fname)))
    return out


def _findings(trials: list[dict]) -> set[str]:
    keys = set()
    for t in trials:
        for e in t.get("execution_log", []):
            for eff in e.get("confirmed_effects", []):
                if eff.get("status") == "confirmed":
                    keys.add(eff["key"])
    return keys


def _condition_summary(mission: str, condition: str) -> dict:
    trials = _load_trials(mission, condition)
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

    print("\n=== Per-mission, per-condition results ===")
    print(f"{'mission':28s} {'condition':18s} {'n':>3s} {'succ':>4s} {'rate':>6s} "
          f"{'mean_p':>7s} {'median_p':>9s} {'findings':>9s} {'branch@1':>9s}")
    for mission in MISSIONS:
        for condition in CONDITIONS:
            s = all_summaries[mission][condition]
            print(f"{mission:28s} {condition:18s} {s['n_trials']:>3d} {s['successes']:>4d} "
                  f"{s['success_rate']:>6.1%} "
                  f"{(s['mean_prompts_to_success'] or 0):>7.2f} "
                  f"{(s['median_prompts_to_success'] or 0):>9.2f} "
                  f"{s['n_distinct_findings']:>9d} "
                  f"{(s['mean_step1_branching_width'] or 0):>9.2f}")

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
        succ = sum(all_summaries[m][condition]["successes"] for m in MISSIONS)
        all_prompts_success = []
        for m in MISSIONS:
            trials = _load_trials(m, condition)
            all_prompts_success += [t["prompts_used"] for t in trials if t.get("outcome") == "SUCCESS"]
        overall[condition] = {
            "n_trials": n, "successes": succ, "success_rate": succ / n if n else 0.0,
            "mean_prompts_to_success": statistics.mean(all_prompts_success) if all_prompts_success else None,
            "median_prompts_to_success": statistics.median(all_prompts_success) if all_prompts_success else None,
            "bootstrap_ci_prompts_to_success": (
                str(bootstrap_mean_ci(all_prompts_success)) if len(all_prompts_success) >= 2 else None
            ),
        }
        print(f"{condition:18s} {succ}/{n} = {succ/n:.1%}" if n else f"{condition:18s} n=0")

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

    path = save_result("exp12_branching_benchmark", {
        "run_dir": RUN_DIR,
        "conditions": list(CONDITIONS),
        "missions": list(MISSIONS),
        "per_mission_per_condition": all_summaries,
        "per_mission_stat_comparisons": stat_comparisons,
        "overall_per_condition": overall,
        "overall_stat_comparisons": overall_stat_comparisons,
    })
    print(f"\nSaved: {path}")


if __name__ == "__main__":
    main()
