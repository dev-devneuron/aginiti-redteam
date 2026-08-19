"""Experiment 3 -- does understanding-first planning discover MORE unique
security behaviors than exploit-first, BFS-only, random, or fixed-order
execution, under an identical, tight budget?

Claim under test (docs/EVIDENCE_AND_EVALUATION.md, "Adaptive planning"):
Aginiti's full utility planner (info gain + business impact + path
progress + gap priority + hypothesis priority) covers more of a target's
behavior space per prompt than policies that only pursue the mission
(exploit-first / GreedyBusinessImpactPlanner), only reason about graph
structure (BFSOnlyPlanner), or don't reason about the graph at all
(Random, Static).

Live experiment (real Groq calls) against the mock Payroll/Slack/GitHub
target (aginiti/target/demo_agent.py, 21-operator/3-branch library) --
the one target this project has full control over and can afford to run
many conditions against, per the same "regression/iteration target, never
scored as RQ1 evidence" role documented in analysis_plan.md. This
experiment is NOT RQ1 (that's Experiment 4, against a real external
target) -- it isolates a narrower, still-real question: does the planning
STRATEGY change how much of a KNOWN, fixed operator library's behavior
space gets covered within budget.

`stop_on_mission_success=False` for every condition: this experiment is
about breadth of understanding under a fixed budget, not speed to a single
compromise -- matching the user's framing exactly ("discover more unique
security behaviors... under the same budget"), not "wins the mission
faster" (that's a different question, tested by Experiment 4).

Metrics per trial:
  - distinct_resolved_claims: claim keys that reached CONFIRMED/REFUTED
    (a raised-and-ANSWERED question, not just a hypothesis)
  - security_relevant_confirmed: CONFIRMED claims tagged trust_edge or
    mission_outcome -- the categories analyst queries treat as actual
    security findings, not just capability bookkeeping
  - insight_count: one post-hoc synthesize_insights() call per trial
    (BEHAVIORAL + SECURITY insight count) -- deliberately POST-HOC (one
    call per trial, not per round) to keep this experiment's LLM cost
    bounded while still measuring synthesized understanding, not just raw
    claim count

Resumable, matching benchmark.py's own pattern: each (condition, trial)
pair's result is written to disk immediately; a rerun skips any pair
already present, so a run interrupted by a rate limit resumes for free.
"""
from __future__ import annotations

import dataclasses
import os
import sys
import time

sys.path.insert(0, ".")

from aginiti.campaign import run_campaign
from aginiti.graph.insights import synthesize_insights
from aginiti.graph.queries import latest_claims
from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME, CATEGORY_TRUST_EDGE
from aginiti.logging_utils import campaign_result_to_dict, load_json, save_json
from aginiti.mission import Mission
from aginiti.operators.definitions import build_library
from aginiti.planner.aginiti_planner import AginitiPlanner
from aginiti.planner.variants import BFSOnlyPlanner, GreedyBusinessImpactPlanner
from aginiti.policies.aginiti_policy import AginitiPolicy
from aginiti.policies.random_policy import RandomPolicy
from aginiti.policies.static_policy import StaticPolicy
from aginiti.scenarios import multi_path_mission
from aginiti.stats import bootstrap_mean_ci, sign_test
from aginiti.target.demo_agent import DemoAgent
from experiments.groq_quota import is_rate_limit_error, preflight_check
from experiments.results_io import save_result, RESULTS_DIR

# Lowered from an earlier 2/10 after this experiment hit Groq's per-org daily
# cap partway through its first trial (see docs/ROADMAP.md's "How we got
# here" -- the same constraint documented since early in the project, hit
# again for real). 1 trial x 5 conditions x budget=8 is small enough to
# plausibly finish inside a single quota window; raise EXP3_N_TRIALS via
# env var once a fresh window is confirmed to have real headroom.
N_TRIALS = int(os.environ.get("EXP3_N_TRIALS", "1"))
BUDGET = int(os.environ.get("EXP3_BUDGET", "8"))
BASE_SEED = 2000
RAW_DIR = os.path.join(RESULTS_DIR, "exp3_raw")

CONDITIONS = ("random", "static", "aginiti", "exploit_first", "bfs_only")


def _build_policy(condition: str, seed: int):
    if condition == "random":
        return RandomPolicy(seed=seed)
    if condition == "static":
        return StaticPolicy()
    if condition == "aginiti":
        return AginitiPolicy(AginitiPlanner(), name="aginiti")
    if condition == "exploit_first":
        return AginitiPolicy(GreedyBusinessImpactPlanner(), name="exploit_first")
    if condition == "bfs_only":
        return AginitiPolicy(BFSOnlyPlanner(), name="bfs_only")
    raise ValueError(condition)


def _security_relevant_count(ssg) -> int:
    return sum(
        1 for c in latest_claims(ssg)
        if c.status == ClaimStatus.CONFIRMED
        and ssg.claim_category.get(c.key) in (CATEGORY_TRUST_EDGE, CATEGORY_MISSION_OUTCOME)
    )


def _run_one(condition: str, trial: int, mission: Mission, library) -> dict:
    seed = BASE_SEED + trial
    agent = DemoAgent(seed=seed)
    policy = _build_policy(condition, seed)
    t0 = time.time()
    result = run_campaign(mission, library, agent=agent, policy=policy,
                           max_steps=BUDGET, seed=seed, stop_on_mission_success=False)
    elapsed = time.time() - t0

    all_claims = latest_claims(result.ssg)
    resolved = [c for c in all_claims if c.status != ClaimStatus.HYPOTHESIZED]
    insights = synthesize_insights(result.ssg, "mock Payroll/Slack/GitHub target (Experiment 3)",
                                    library=library, executed_ids=frozenset(result.ssg.operator_stats),
                                    seed=seed)
    behavioral = sum(1 for i in insights if i.category.value == "behavioral")
    security = sum(1 for i in insights if i.category.value == "security")
    gaps = sum(1 for i in insights if i.category.value == "knowledge_gap")

    record = campaign_result_to_dict(condition, trial, seed, result)
    record["elapsed_seconds"] = elapsed
    record["distinct_resolved_claims"] = len(resolved)
    record["security_relevant_confirmed"] = _security_relevant_count(result.ssg)
    record["insight_behavioral_count"] = behavioral
    record["insight_security_count"] = security
    record["insight_gap_count"] = gaps
    return record


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
        for condition in CONDITIONS:
            path = os.path.join(RAW_DIR, f"{condition}_trial{trial:02d}.json")
            if os.path.exists(path):
                print(f"trial {trial} | {condition:14s} -> (already logged, skipping)")
                records[condition].append(load_json(path))
                continue
            try:
                record = _run_one(condition, trial, mission, library)
            except Exception as e:
                if is_rate_limit_error(e):
                    print(f"trial {trial} | {condition:14s} -> RATE LIMITED mid-campaign: {e}")
                    print("Stopping here -- every (condition, trial) pair completed so far is already "
                          "saved to disk and will be skipped (not re-run, not lost) on the next attempt.")
                    rate_limited = True
                    break
                raise
            save_json(path, record)
            records[condition].append(record)
            print(f"trial {trial} | {condition:14s} -> distinct_resolved={record['distinct_resolved_claims']} "
                  f"security_relevant={record['security_relevant_confirmed']} "
                  f"insights(b/s/g)={record['insight_behavioral_count']}/"
                  f"{record['insight_security_count']}/{record['insight_gap_count']} "
                  f"prompts={record['prompts_used']} ({record['elapsed_seconds']:.1f}s)")

    summary = {}
    for condition, rows in records.items():
        if not rows:
            continue
        distinct = [r["distinct_resolved_claims"] for r in rows]
        security = [r["security_relevant_confirmed"] for r in rows]
        summary[condition] = {
            "n_trials": len(rows),
            "distinct_resolved_claims_mean": sum(distinct) / len(distinct),
            "distinct_resolved_claims_ci": str(bootstrap_mean_ci(distinct)) if len(distinct) > 1 else None,
            "security_relevant_mean": sum(security) / len(security),
            "insight_total_mean": sum(r["insight_behavioral_count"] + r["insight_security_count"] for r in rows) / len(rows),
        }

    comparisons = {}
    if records.get("aginiti") and len(records["aginiti"]) == N_TRIALS:
        aginiti_distinct = [r["distinct_resolved_claims"] for r in records["aginiti"]]
        for other in ("exploit_first", "bfs_only", "random", "static"):
            if len(records.get(other, [])) == N_TRIALS:
                other_distinct = [r["distinct_resolved_claims"] for r in records[other]]
                st = sign_test(aginiti_distinct, other_distinct)
                comparisons[f"aginiti_vs_{other}"] = {
                    "aginiti_mean": sum(aginiti_distinct) / len(aginiti_distinct),
                    "other_mean": sum(other_distinct) / len(other_distinct),
                    "sign_test": st.interpret(), "p_value": st.p_value,
                    "n_positive": st.n_positive, "n_negative": st.n_negative, "n_ties": st.n_ties,
                }

    print("\n=== Experiment 3 summary ===")
    for condition, s in summary.items():
        print(f"{condition:14s} n={s['n_trials']} distinct_resolved={s['distinct_resolved_claims_mean']:.2f} "
              f"security_relevant={s['security_relevant_mean']:.2f} insights={s['insight_total_mean']:.2f}")
    print()
    for name, c in comparisons.items():
        print(f"{name}: aginiti={c['aginiti_mean']:.2f} vs other={c['other_mean']:.2f} -- {c['sign_test']}")

    path = save_result("exp3_understanding_first_vs_baselines", {
        "n_trials": N_TRIALS, "budget": BUDGET, "conditions": CONDITIONS,
        "summary": summary, "comparisons": comparisons,
    })
    print(f"\nsaved summary to {path} (raw per-trial records in {RAW_DIR})")


if __name__ == "__main__":
    main()
