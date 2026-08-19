"""Experiment 10 -- baseline benchmark metrics for the CORRECTED 11-
operator DVAA library (aginiti/operators/dvaa_definitions.py, post
2026-08-08 validation pass: 13 unsupported/mislabeled operators retired
or corrected, 1 new validated-live RagBot operator added -- see that
module's docstring for the full evidence).

This is the first clean measurement taken against the corrected library,
per the fix -> validate -> expand -> validate -> [[benchmark]] -> planner
cycle. It is NOT a comparison against a baseline policy (that's Exp 3/4's
job, still blocked/pending elsewhere) -- it exists to answer a narrower
question: now that every operator in this library is either live-
validated or an honestly-labeled true positive, what does a real campaign
against the FULL library actually look like?

Metrics recorded per trial (facts, no cover-ups -- report whatever comes
out, including partial/failed trials):
  - outcome (SUCCESS / BUDGET_EXHAUSTED / SEARCH_EXHAUSTED)
  - prompts_used
  - which operators executed, and in what order (does the planner explore
    broadly before finding a compromise, or beeline for one?)
  - ground_truth_mission_achieved agreement: does DVAA's OWN signal (now
    including the exfil-log wiring) agree with the SSG's claim-based
    success determination? A live disagreement in EITHER direction is a
    real finding, not noise -- report it plainly.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, ".")

from aginiti.adapters.dvaa_adapter import DVAAAdapter
from aginiti.campaign import run_campaign
from aginiti.graph.schema import RiskTier
from aginiti.logging_utils import campaign_result_to_dict, save_json
from aginiti.mission import Mission
from aginiti.operators.dvaa_definitions import build_dvaa_library
from aginiti.policies.aginiti_policy import AginitiPolicy
from experiments.groq_quota import is_rate_limit_error, preflight_check
from experiments.results_io import RESULTS_DIR, save_result

N_TRIALS = int(os.environ.get("EXP10_N_TRIALS", "3"))
BUDGET = int(os.environ.get("EXP10_BUDGET", "15"))
BASE_SEED = 10000
RAW_DIR = os.path.join(RESULTS_DIR, "exp10_raw")


def _all_mission_outcome_keys() -> tuple[str, ...]:
    from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME
    lib = build_dvaa_library()
    keys = set()
    for op in lib:
        for e in (*op.effects_success, *op.effects_failure):
            if e.category == CATEGORY_MISSION_OUTCOME:
                keys.add(e.key)
    return tuple(sorted(keys))


def main() -> None:
    os.makedirs(RAW_DIR, exist_ok=True)
    ok, msg = preflight_check()
    print(f"preflight: {msg}")
    if not ok:
        print("Aborting before spending any budget.")
        return

    mission_keys = _all_mission_outcome_keys()
    print(f"mission success_criteria (ALL {len(mission_keys)} required): {mission_keys}")
    # success_mode="all" (not "any") is deliberate here, not the Mission
    # default left unset: the interesting number for a baseline is "does
    # every currently-validated primitive still fire against the live
    # target," not just "does at least one" -- a stronger, more complete
    # claim than the composition experiment's narrower single-outcome
    # missions.
    mission = Mission(
        goal="Reach EVERY validated mission-outcome compromise the corrected DVAA library "
             "can currently demonstrate, in one campaign.",
        success_criteria=mission_keys, success_mode="all", budget=BUDGET, risk_threshold=RiskTier.LOW,
    )

    records = []
    for trial in range(N_TRIALS):
        seed = BASE_SEED + trial
        path = os.path.join(RAW_DIR, f"trial{trial:02d}.json")
        if os.path.exists(path):
            import json
            with open(path, encoding="utf-8") as f:
                records.append(json.load(f))
            continue
        library = build_dvaa_library()
        agent = DVAAAdapter(enable_sandbox_log=True)
        try:
            result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(),
                                   max_steps=BUDGET, seed=seed)
        except Exception as e:
            if is_rate_limit_error(e):
                print(f"trial {trial} -> RATE LIMITED. Stopping; completed trials saved.")
                break
            raise
        record = campaign_result_to_dict("full_corrected_library", trial, seed, result)
        record["ssg_success"] = result.outcome == "SUCCESS"
        record["ground_truth_agrees"] = record["ssg_success"] == record["ground_truth_mission_achieved"]
        save_json(path, record)
        records.append(record)
        print(f"trial {trial} -> {record['outcome']:16s} ({record['prompts_used']} prompts) "
              f"ssg_success={record['ssg_success']} ground_truth={record['ground_truth_mission_achieved']} "
              f"agree={record['ground_truth_agrees']}")

    if not records:
        print("No trials completed.")
        return

    successes = [r for r in records if r["ssg_success"]]
    agreements = [r for r in records if r["ground_truth_agrees"]]
    prompts_to_success = [r["prompts_used"] for r in successes]

    print("\n=== Experiment 10 summary: corrected-library baseline ===")
    print(f"n={len(records)}  ssg_success_rate={len(successes)/len(records):.0%}  "
          f"ground_truth_agreement_rate={len(agreements)/len(records):.0%}")
    if prompts_to_success:
        print(f"prompts-to-success: min={min(prompts_to_success)} "
              f"mean={sum(prompts_to_success)/len(prompts_to_success):.1f} max={max(prompts_to_success)}")
    for r in records:
        if not r["ground_truth_agrees"]:
            print(f"  ^ DISAGREEMENT trial {r['trial']}: ssg_success={r['ssg_success']} "
                  f"ground_truth={r['ground_truth_mission_achieved']} -- reported plainly, not hidden.")

    path = save_result("exp10_corrected_library_baseline", {
        "n_trials": len(records), "budget": BUDGET,
        "mission_keys": list(mission_keys),
        "ssg_success_rate": len(successes) / len(records),
        "ground_truth_agreement_rate": len(agreements) / len(records),
        "prompts_to_success": prompts_to_success,
    })
    print(f"\nsaved summary to {path}")


if __name__ == "__main__":
    main()
