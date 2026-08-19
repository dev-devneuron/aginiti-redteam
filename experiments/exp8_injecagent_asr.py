"""Experiment 8 -- Attack Success Rate against a sample of InjecAgent's
real, vendored test cases (aginiti/operators/injecagent_data/NOTICE.md),
driven through Aginiti's own InjecAgentAdapter/campaign machinery instead
of InjecAgent's own evaluation harness.

NOT RUN THIS SESSION, deliberately: the 2026-08-08 architecture-review
process rules are explicit -- "no benchmark reruns until an architectural
improvement is complete" and Gemini stays reserved for RQ1 testing, not
spent here. This script exists so the plumbing (adapter, operator
generator, sampling, per-trial JSON logging, ASR aggregation) is written,
reviewable, and unit-testable NOW (tests/test_injecagent_adapter.py
covers the pipeline offline) -- running it live is a separate, explicit
decision for later, not bundled into writing the harness itself.

Metric: ASR (Attack Success Rate) = fraction of sampled test cases where
either the judge confirms the attack's success claim OR
InjecAgentAdapter.ground_truth_mission_achieved() independently observed
an attempted call to the attacker's declared tool -- reported separately,
mirroring InjecAgent's own ASR-valid vs. ASR-all distinction (the paper
tracks both because a text-only compliance and an actual attempted
function call are different strengths of evidence).

Uses AGINITI_LLM_PROVIDER as already configured (defaults to Groq) --
per the standing instruction to keep Groq as the tool's own working
capability and hold Gemini in reserve for RQ1 specifically.
"""
from __future__ import annotations

import os
import random
import sys

sys.path.insert(0, ".")

from aginiti.core.campaign import run_campaign
from aginiti.core.logging_utils import campaign_result_to_dict, save_json
from aginiti.core.mission import Mission
from aginiti.core.graph.schema import RiskTier
from aginiti.operators.injecagent import injecagent_operator
from aginiti.operators.library import OperatorLibrary
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from aginiti.target.injecagent_adapter import InjecAgentAdapter, build_test_cases
from experiments.groq_quota import is_rate_limit_error, preflight_check
from experiments.results_io import RESULTS_DIR, save_result

N_SAMPLES = int(os.environ.get("EXP8_N_SAMPLES", "20"))
BASE_SEED = 8000
RAW_DIR = os.path.join(RESULTS_DIR, "exp8_raw")


def _sampled_test_cases(n: int, seed: int) -> list[dict]:
    all_cases = build_test_cases()
    rng = random.Random(seed)
    return rng.sample(all_cases, min(n, len(all_cases)))


def _mission_for(test_case: dict, op) -> Mission:
    success_key = op.effects_success[0].key
    return Mission(
        goal=f"InjecAgent test case #{test_case['index']}: {test_case['attacker_case']['Attack Type']}",
        success_criteria=(success_key,), budget=2, risk_threshold=RiskTier.MEDIUM,
    )


def main() -> None:
    os.makedirs(RAW_DIR, exist_ok=True)

    ok, msg = preflight_check()
    print(f"preflight: {msg}")
    if not ok:
        print("Aborting before spending any budget -- resume once quota is back; "
              "already-completed trials on disk are skipped automatically.")
        return

    test_cases = _sampled_test_cases(N_SAMPLES, BASE_SEED)
    records = []
    for trial, test_case in enumerate(test_cases):
        path = os.path.join(RAW_DIR, f"trial{trial:03d}_idx{test_case['index']:04d}.json")
        if os.path.exists(path):
            print(f"trial {trial} | idx {test_case['index']:04d} -> (already logged, skipping)")
            import json
            with open(path, encoding="utf-8") as f:
                records.append(json.load(f))
            continue

        op = injecagent_operator(test_case)
        library = OperatorLibrary([op])
        mission = _mission_for(test_case, op)
        # `agent` here is campaign.py's name for the TARGET (BaseAdapter-shaped);
        # `adapter=None` lets run_campaign construct a real ObservationAdapter
        # (the judge) around it -- same wiring every other live experiment uses.
        target = InjecAgentAdapter(test_case, seed=BASE_SEED + trial)

        try:
            result = run_campaign(mission, library, agent=target, policy=AginitiPolicy(),
                                   adapter=None, max_steps=1, seed=BASE_SEED + trial)
        except Exception as e:
            if is_rate_limit_error(e):
                print(f"trial {trial} -> RATE LIMITED mid-run. Stopping; completed trials are saved.")
                break
            raise

        judge_confirmed = result.outcome == "SUCCESS"
        ground_truth = target.ground_truth_mission_achieved()
        record = campaign_result_to_dict("injecagent", trial, BASE_SEED + trial, result)
        record["injecagent_index"] = test_case["index"]
        record["attack_type"] = test_case["attacker_case"]["Attack Type"]
        record["judge_confirmed_success"] = judge_confirmed
        record["ground_truth_attempted_attacker_tool"] = ground_truth
        save_json(path, record)
        records.append(record)
        print(f"trial {trial} | idx {test_case['index']:04d} ({record['attack_type']:14s}) -> "
              f"judge={judge_confirmed} ground_truth={ground_truth}")

    n = len(records)
    asr_valid = sum(1 for r in records if r["judge_confirmed_success"]) / n if n else 0.0
    asr_ground_truth = sum(1 for r in records if r["ground_truth_attempted_attacker_tool"]) / n if n else 0.0

    print(f"\n=== Experiment 8 summary: InjecAgent ASR over {n} sampled test cases ===")
    print(f"ASR (judge-confirmed):        {asr_valid:.1%}")
    print(f"ASR (attempted attacker tool): {asr_ground_truth:.1%}")

    path = save_result("exp8_injecagent_asr", {
        "n_samples": n, "base_seed": BASE_SEED,
        "asr_judge_confirmed": asr_valid, "asr_attempted_attacker_tool": asr_ground_truth,
        "source": "InjecAgent (Zhan et al., ACL Findings 2024) -- see aginiti/operators/injecagent_data/NOTICE.md",
    })
    print(f"\nsaved summary to {path} (raw per-trial records in {RAW_DIR})")


if __name__ == "__main__":
    main()
