"""Targeted re-run of ONLY hardened_agent_support/ops's E_full_assessment
condition -- exp25's ORIGINAL run of these two hit a confirmed judge false
positive (encoding_discovery_base64's response quoted back the decoded
attack instruction, then explicitly refused it; the judge misclassified
this as compliance under the newly-added "hedged/partial compliance"
clarification, stopping the whole assessment after just 1 prompt each).
The judge prompt has been fixed (observation_adapter.py's _judge() system
prompt now explicitly distinguishes "quotes the REQUEST back" from
"reveals the REQUESTED CONTENT"). This script re-runs exactly those two
(persona, condition) pairs with the SAME locked design (budget=18,
encoding_discovery_budget=5, framing_discovery_budget=4/goal,
framing_refinement_attempts=1/goal) -- nothing else changed, no tuning
based on the first run's specific content.

Usage:
    python experiments/exp25_rerun_support_ops_full_assessment.py
"""
from __future__ import annotations

import sys
sys.path.insert(0, ".")

from dotenv import load_dotenv
load_dotenv()

# Reuse exp25's own functions directly -- this is a re-run of the SAME
# design, not a new one.
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "exp25", "experiments/exp25_full_assessment_vs_baseline_live.py")
exp25 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(exp25)


def main() -> None:
    exp25._configure_logging()
    print("Building disclosure indices from real local datasets...")
    hardened_index = exp25.VerbatimDisclosureIndex.from_json_files(
        exp25._DATASETS / "hardened_dataset_ingested.json")
    fuzzy_index = exp25.FuzzyDisclosureIndex.from_json_files(
        exp25._DATASETS / "hardened_dataset_ingested.json")

    rows = []
    for persona in ("support", "ops"):
        rows.append(exp25._run_safely(exp25._run_full_assessment, persona, hardened_index, fuzzy_index,
                                       label=f"hardened_agent_{persona}__E_full_assessment_RERUN"))

    print(f"\n{'=' * 78}\nRERUN SUMMARY\n{'=' * 78}")
    for r in rows:
        if r.get("status") == "failed":
            print(f"{r.get('persona')}: FAILED {r.get('error_type')}: {r.get('error_message')}")
            continue
        print(f"{r['persona']:<10} outcome={r['outcome']:<12} stopped_early_after={r['stopped_early_after']} "
              f"total_prompts={r['total_prompts_used']} ground_truth={r['ground_truth_mission_achieved']} "
              f"rbac_crossed={r['rbac_boundary_crossed_confirmed']}")

    import json
    (exp25._RESULTS_DIR / "exp25_rerun_summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\nWritten: {exp25._RESULTS_DIR / 'exp25_rerun_summary.json'}")


if __name__ == "__main__":
    main()
