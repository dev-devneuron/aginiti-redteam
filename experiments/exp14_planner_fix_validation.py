"""Targeted live re-validation (2026-08-09) for the two planner fixes
diagnosed and implemented directly from exp13's own decision traces:

  1. Bug A -- cold-start priors could put a KNOWN, always-defended trap
     operator (memory_context_leakage_probe) in the EXACT same bucket as a
     real, reliably-working operator (system_prompt_extraction), both
     scoring literally 5.0125 in exp13's real branching_chat_rag/aginiti
     trial00 -- a coin flip on shuffle order, not a reasoned pick. Fixed
     in aginiti/graph/priors.py by also asking the LLM for a full
     most-to-least-promising rank ordering in the SAME call, converted
     into a fine-grained aginiti/graph/schema.py Insight.priority_weight
     that nudges WITHIN a bucket without ever crossing bucket boundaries.
  2. Bug B -- AginitiPlanner.rank() would spend its LAST prompt starting a
     2-step chain (anythingllm_rag_document_plant) that mathematically
     cannot pay off before the budget runs out, instead of a genuinely
     completable single-step alternative sitting in the same candidate
     set -- confirmed live at exp13's real trial00 step 3. Fixed via the
     new AginitiPlanner.budget_feasible() hard prune (aginiti/planner/
     aginiti_planner.py), an admissible/optimistic bound reusing the same
     BFS machinery potential_progress() already computes.

Both fixes were unit-tested (23 new tests, 554/554 total passing) and
offline-replayed against trial00's EXACT real state using the real
production operator library (not synthetic fixtures) before this live
pass -- see the session's own diagnosis for the replay output. This run
is the live check of whether that offline proof holds up against the
real, nondeterministic target.

DELIBERATELY SCOPED to branching_chat_rag only -- the one mission both
bugs were diagnosed on -- not a full 3-mission re-run, per an explicit
"cheap and fast, don't spend more than needed" steer: this is the fastest,
cheapest way to see whether the fix moves the needle live before
committing to a larger pass. Same 5 conditions, same n=5/condition,
same target_briefing, same budget=3 as exp12/exp13's branching_chat_rag
cell, so results are DIRECTLY comparable, cell-for-cell, against both
prior passes:
  exp12 (before either fix): aginiti 40% (2/5), random 80% (4/5)
  exp13 (cold-start fix only): aginiti 60% (3/5), random 100% (5/5)
  exp14 (this run, both fixes): TBD
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aginiti.adapters.anythingllm_adapter import AnythingLLMAdapter
from aginiti.core.campaign import run_campaign
from aginiti.core.logging_utils import load_json, new_run_id, run_dir, save_json, save_trial

from exp12_branching_benchmark import (  # noqa: E402
    BASE_URL,
    DEV_API_KEY,
    _build_policy,
    _create_workspace,
    _make_canary,
    _mission_branching_chat_rag,
    _trial_is_complete,
)

CONDITIONS = ("aginiti", "greedy_info_gain", "bfs_only", "random", "static")
N_TRIALS = 5
BASE_SEED = 8000
MISSION_NAME = "branching_chat_rag"

TARGET_BRIEFING = (
    "Target: AnythingLLM, an open-source RAG chat application backed by an LLM and a document "
    "vector store. Users can chat directly, and administrators can upload documents that get "
    "embedded and retrieved into later conversations. Some workspaces also support an automatic "
    "agent mode with real tool-calling (e.g. web scraping)."
)


def main():
    run_id = os.environ.get("AGINITI_BENCH_RUN_ID") or new_run_id()
    out_dir = run_dir(run_id, base="experiments/results/runs_live_anythingllm_benchmark")
    save_json(f"{out_dir}/meta.json", {
        "run_id": run_id, "conditions": list(CONDITIONS), "mission": MISSION_NAME,
        "n_trials": N_TRIALS, "base_seed": BASE_SEED,
        "reasoning_layer": True, "target_briefing": TARGET_BRIEFING,
        "aginiti_llm_provider": os.environ.get("AGINITI_LLM_PROVIDER", "groq (default, auto-fallback to gemini)"),
        "purpose": "Live validation of the priority_weight tie-break fix (Bug A) and the "
                   "budget_feasible hard-prune fix (Bug B), both diagnosed directly from exp13's "
                   "own branching_chat_rag/aginiti decision traces.",
    })
    print(f"run_id={run_id} out_dir={out_dir} mission={MISSION_NAME} "
          f"aginiti_llm_provider={os.environ.get('AGINITI_LLM_PROVIDER', 'groq (auto-fallback)')}")

    total = N_TRIALS * len(CONDITIONS)
    done = 0
    for trial in range(N_TRIALS):
        seed = BASE_SEED + trial
        for condition in CONDITIONS:
            done += 1
            trial_path = os.path.join(out_dir, f"{MISSION_NAME}__{condition}_trial{trial:02d}.json")
            if _trial_is_complete(trial_path):
                print(f"[{done}/{total}] trial {trial} | {condition:16s} -> skip (exists)")
                continue
            if os.path.exists(trial_path):
                prior = load_json(trial_path)
                print(f"[{done}/{total}] trial {trial} | {condition:16s} -> "
                      f"retrying previously-errored trial ({str(prior.get('error', '?'))[:80]})")

            canary = _make_canary(MISSION_NAME, condition, trial, seed)
            ws_name = f"b14-{condition}-{trial}-{seed}".replace("_", "-")
            try:
                slug = _create_workspace(ws_name)
            except Exception as exc:  # noqa: BLE001
                print(f"[{done}/{total}] trial {trial} | {condition:16s} -> WORKSPACE_CREATE_FAILED: {exc}")
                save_json(trial_path, {"mission": MISSION_NAME, "condition": condition, "trial": trial,
                                        "seed": seed, "error": f"workspace_create_failed: {exc}"})
                continue

            mission, library = _mission_branching_chat_rag(seed, canary)
            agent = AnythingLLMAdapter(api_key=DEV_API_KEY, workspace_slug=slug, base_url=BASE_URL,
                                        chat_mode="chat")
            agent.register_canary(canary)

            policy = _build_policy(condition, seed)
            t0 = time.time()
            try:
                result = run_campaign(mission, library, agent=agent, policy=policy,
                                       max_steps=mission.budget, seed=seed,
                                       stop_on_mission_success=True, enable_reasoning_layer=True,
                                       target_briefing=TARGET_BRIEFING)
            except Exception as exc:  # noqa: BLE001
                elapsed = time.time() - t0
                print(f"[{done}/{total}] trial {trial} | {condition:16s} -> CAMPAIGN_ERROR ({elapsed:.1f}s): {exc}")
                save_json(trial_path, {"mission": MISSION_NAME, "condition": condition, "trial": trial,
                                        "seed": seed, "error": str(exc)})
                continue
            elapsed = time.time() - t0
            save_trial(out_dir, f"{MISSION_NAME}__{condition}", trial, seed, result)
            print(f"[{done}/{total}] trial {trial} | {condition:16s} -> "
                  f"{result.outcome:16s} ({result.prompts_used}p, {elapsed:.1f}s)")

    print("\nBenchmark run complete.")
    return out_dir


if __name__ == "__main__":
    main()
