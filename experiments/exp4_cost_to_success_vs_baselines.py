"""Experiment 4 -- does Aginiti's planner reach compromise faster / with
fewer probes than Random and Static-enumeration baselines?

Claim under test: this is the project's FOUNDING question (RQ1,
analysis_plan.md), and it has never been run to completion at any real
target (docs/EVIDENCE_AND_EVALUATION.md Section 4, item 1 -- the single
most consequential open item on the whole evidence ledger).

IMPORTANT SCOPE NOTE, stated once here and repeated in every place this
experiment's results are cited: this run is against the MOCK Payroll/
Slack/GitHub target (aginiti/target/demo_agent.py), NOT the frozen RQ1
target (damn-vulnerable-llm-agent). analysis_plan.md is explicit that the
mock target is a "regression target... used for CI/fast iteration only.
Never scored as evidence for RQ1." This experiment does not violate that
rule -- it is NOT presented as RQ1 evidence. It exists because the mock
target is the only target in this project with enough real branching
difficulty (21 operators, 3 independently-gated paths) for a cost-to-
success comparison to have room to show a difference at all: DVLA (the
actual RQ1 target) currently has both its known attack vectors BLOCKED
(override_blocked and injection_blocked both CONFIRMED, per
runs/dvla_target_profile.md) -- every condition would score 0% success
there today, which tests nothing about planning quality. This experiment
answers a narrower, honestly-scoped question: "on a target where
compromise IS achievable, does Aginiti's utility-based ranking reach it
faster than picking blind or checking a fixed list?" -- a necessary
precondition for RQ1 to even be worth running at the real target, not a
replacement for it.

3 conditions (random, static, aginiti -- memory_guided omitted to keep
this pilot's live-call cost down; it can be added in a later pass without
changing this script's structure), same seed per trial index across
conditions (matching benchmark.py's own RQ1 methodology exactly), default
stop_on_mission_success=True (this IS about speed-to-compromise, unlike
Experiment 3's stop_on_mission_success=False).

Metrics: success rate, prompts-used-to-success (mean + bootstrap CI, since
free-tier trial counts are always small here), operators_considered_total
(a proxy for search effort spent, not just prompts).
"""
from __future__ import annotations

import dataclasses
import os
import sys
import time

sys.path.insert(0, ".")

from aginiti.core.campaign import run_campaign
from aginiti.core.logging_utils import campaign_result_to_dict, load_json, save_json
from aginiti.operators.definitions import build_library
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from aginiti.core.policies.random_policy import RandomPolicy
from aginiti.core.policies.static_policy import StaticPolicy
from aginiti.core.scenarios import multi_path_mission
from aginiti.core.stats import bootstrap_mean_ci, fisher_exact_two_sided
from aginiti.target.demo_agent import DemoAgent
from experiments.groq_quota import is_rate_limit_error, preflight_check
from experiments.results_io import save_result, RESULTS_DIR

# Lowered from an earlier 3/15 for the same reason as Experiment 3 -- see
# that script's comment and docs/ROADMAP.md's documented Groq per-org daily
# cap. Raise via env var once a fresh quota window is confirmed to have
# real headroom (run experiments/groq_quota.py's preflight_check first).
N_TRIALS = int(os.environ.get("EXP4_N_TRIALS", "2"))
BUDGET = int(os.environ.get("EXP4_BUDGET", "10"))
BASE_SEED = 3000
RAW_DIR = os.path.join(RESULTS_DIR, "exp4_raw")
CONDITIONS = ("random", "static", "aginiti")


def _build_policy(condition: str, seed: int):
    if condition == "random":
        return RandomPolicy(seed=seed)
    if condition == "static":
        return StaticPolicy()
    if condition == "aginiti":
        return AginitiPolicy()
    raise ValueError(condition)


def main() -> None:
    os.makedirs(RAW_DIR, exist_ok=True)
    mission = dataclasses.replace(multi_path_mission(), budget=BUDGET)
    library = build_library()

    ok, msg = preflight_check()
    print(f"preflight: {msg}")
    if not ok:
        print("Aborting before spending any campaign budget -- resume this script once quota is back; "
              "already-completed (condition, trial) pairs on disk will be skipped automatically.")
        return

    records: dict[str, list[dict]] = {c: [] for c in CONDITIONS}
    rate_limited = False
    for trial in range(N_TRIALS):
        if rate_limited:
            break
        seed = BASE_SEED + trial
        for condition in CONDITIONS:
            path = os.path.join(RAW_DIR, f"{condition}_trial{trial:02d}.json")
            if os.path.exists(path):
                print(f"trial {trial} | {condition:10s} -> (already logged, skipping)")
                records[condition].append(load_json(path))
                continue
            agent = DemoAgent(seed=seed)
            policy = _build_policy(condition, seed)
            t0 = time.time()
            try:
                result = run_campaign(mission, library, agent=agent, policy=policy,
                                       max_steps=BUDGET, seed=seed)  # stop_on_mission_success=True (default)
            except Exception as e:
                if is_rate_limit_error(e):
                    print(f"trial {trial} | {condition:10s} -> RATE LIMITED mid-campaign: {e}")
                    print("Stopping here -- every (condition, trial) pair completed so far is already "
                          "saved to disk and will be skipped (not re-run, not lost) on the next attempt.")
                    rate_limited = True
                    break
                raise
            elapsed = time.time() - t0
            record = campaign_result_to_dict(condition, trial, seed, result)
            record["elapsed_seconds"] = elapsed
            save_json(path, record)
            records[condition].append(record)
            print(f"trial {trial} | {condition:10s} -> {record['outcome']:16s} "
                  f"({record['prompts_used']} prompts, {elapsed:.1f}s)")

    summary = {}
    for condition, rows in records.items():
        successes = [r for r in rows if r["outcome"] == "SUCCESS"]
        prompts_on_success = [r["prompts_used"] for r in successes]
        summary[condition] = {
            "n_trials": len(rows),
            "n_successes": len(successes),
            "success_rate": len(successes) / len(rows) if rows else 0.0,
            "mean_prompts_to_success": (sum(prompts_on_success) / len(prompts_on_success)
                                          if prompts_on_success else None),
            "prompts_to_success_ci": (str(bootstrap_mean_ci(prompts_on_success))
                                        if len(prompts_on_success) > 1 else None),
            "mean_operators_considered": sum(r["operators_considered_total"] for r in rows) / len(rows) if rows else 0.0,
        }

    comparisons = {}
    if summary.get("aginiti"):
        a = summary["aginiti"]
        for other in ("random", "static"):
            if summary.get(other):
                o = summary[other]
                p = fisher_exact_two_sided(a["n_successes"], a["n_trials"] - a["n_successes"],
                                            o["n_successes"], o["n_trials"] - o["n_successes"])
                comparisons[f"aginiti_vs_{other}"] = {
                    "aginiti_success_rate": a["success_rate"], "other_success_rate": o["success_rate"],
                    "fisher_p_value": p,
                    "underpowered": (a["n_trials"] + o["n_trials"]) < 40,
                }

    print("\n=== Experiment 4 summary (MOCK TARGET PILOT -- NOT RQ1 evidence, see docstring) ===")
    for condition, s in summary.items():
        mp = f"{s['mean_prompts_to_success']:.1f}" if s["mean_prompts_to_success"] is not None else "N/A"
        print(f"{condition:10s} n={s['n_trials']} success_rate={s['success_rate']:.0%} "
              f"mean_prompts_to_success={mp} mean_operators_considered={s['mean_operators_considered']:.1f}")
    print()
    for name, c in comparisons.items():
        power_note = " (UNDERPOWERED -- n<40)" if c["underpowered"] else ""
        print(f"{name}: {c['aginiti_success_rate']:.0%} vs {c['other_success_rate']:.0%}, "
              f"fisher p={c['fisher_p_value']:.3f}{power_note}")

    path = save_result("exp4_cost_to_success_vs_baselines", {
        "n_trials": N_TRIALS, "budget": BUDGET, "conditions": CONDITIONS,
        "scope_note": "MOCK TARGET PILOT, not RQ1 evidence -- see script docstring",
        "summary": summary, "comparisons": comparisons,
    })
    print(f"\nsaved summary to {path} (raw per-trial records in {RAW_DIR})")


if __name__ == "__main__":
    main()
