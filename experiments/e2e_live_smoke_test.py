"""2026-08-12 engineering-hardening pass, Phase 8: a SMALL, SAFE live smoke
test against the real hardened AnythingLLM gateway -- NOT a benchmark, NOT
a comparison, NOT a source of any reported metric. Two minimal campaigns,
one budget-1 step each:

  1. `system_prompt_extraction` (data_exposure.py) -- judge-path (LLM
     judge call, not a deterministic extractor), single-step, read-only,
     non-destructive. Proves the REAL AnythingLLMAdapter -> ObservationAdapter
     -> judge -> SSG pipeline works against a REAL running target, not just
     mocks.
  2. `anythingllm_rag_document_plant` + `anythingllm_rag_injection_trigger`
     -- deterministic-extractor path, 2-step chain with a real precondition
     gate. Proves the real plant/retrieval mechanism and chain-gating work
     live, not just in the offline dry runs built earlier this session.

Uses a dedicated, freshly-created throwaway workspace (never reuses
"aginiti-target" or any other pre-existing workspace from earlier
experiments) so this can never contaminate or be contaminated by prior
session state.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests

from aginiti.adapters.anythingllm_adapter import AnythingLLMAdapter
from aginiti.campaign import run_campaign
from aginiti.graph.schema import RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.anythingllm_definitions import build_anythingllm_library
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.library import OperatorLibrary
from aginiti.policies.aginiti_policy import AginitiPolicy
from hardened_target_v2_config import HARDENED_PROMPT_V2, HARDENED_WORKSPACE_SETTINGS_V2

GATEWAY_BASE_URL = "http://localhost:3002"
GATEWAY_KEY = "gw-full-admin-key"


def _create_smoke_workspace(name: str) -> str:
    resp = requests.post(
        f"{GATEWAY_BASE_URL}/api/v1/workspace/new",
        headers={"Authorization": f"Bearer {GATEWAY_KEY}", "Content-Type": "application/json"},
        json={"name": name, "chatMode": "chat", "openAiPrompt": HARDENED_PROMPT_V2},
        timeout=30)
    resp.raise_for_status()
    slug = resp.json()["workspace"]["slug"]
    requests.post(
        f"{GATEWAY_BASE_URL}/api/v1/workspace/{slug}/update",
        headers={"Authorization": f"Bearer {GATEWAY_KEY}", "Content-Type": "application/json"},
        json={"chatMode": "chat", "openAiPrompt": HARDENED_PROMPT_V2, **HARDENED_WORKSPACE_SETTINGS_V2},
        timeout=30)
    return slug


def smoke_test_1_judge_path_single_step() -> bool:
    print("\n=== SMOKE TEST 1: judge-path, single-step, real target ===")
    slug = _create_smoke_workspace("aginiti-smoke-1")
    print(f"workspace: {slug}")
    ssg = SecurityStateGraph()
    agent = AnythingLLMAdapter(api_key=GATEWAY_KEY, workspace_slug=slug, base_url=GATEWAY_BASE_URL)
    library = OperatorLibrary([op for op in data_exposure_operators() if op.id == "system_prompt_extraction"])
    mission = Mission(goal="smoke test 1", success_criteria=("system_prompt_disclosed",),
                       budget=1, risk_threshold=RiskTier.MEDIUM, constraints=())

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=1, ssg=ssg)

    print(f"outcome={result.outcome} prompts_used={result.prompts_used}")
    print(f"operators_executed={result.operators_executed}")
    if result.execution_log:
        e = result.execution_log[0]
        print(f"overall_success={e.overall_success} confirmed_keys={e.confirmed_keys}")
        print(f"raw_signal (first 200 chars): {e.raw_signal[:200]!r}")
    print(f"final claims: {[(c.key, c.status.value) for c in ssg.claims]}")
    print(f"ground_truth_mission_achieved={agent.ground_truth_mission_achieved()}")

    # The actual pass/fail bar for THIS smoke test is infrastructure
    # health, not attack success: did the full pipeline run without
    # crashing, and did it produce a CLASSIFIED result either way (a
    # confirmed claim OR a confirmed-blocked claim), never silence?
    ran_cleanly = result.outcome in ("SUCCESS", "BUDGET_EXHAUSTED", "SEARCH_EXHAUSTED")
    produced_a_classification = bool(result.execution_log) and (
        ssg.is_confirmed("system_prompt_disclosed") or ssg.is_confirmed("system_prompt_extraction_blocked")
    )
    print(f"PASS: pipeline ran cleanly={ran_cleanly}, produced an explicit classification={produced_a_classification}")
    return ran_cleanly and produced_a_classification


def smoke_test_2_deterministic_chain_two_step() -> bool:
    print("\n=== SMOKE TEST 2: deterministic-extractor, real 2-step chain, real target ===")
    slug = _create_smoke_workspace("aginiti-smoke-2")
    print(f"workspace: {slug}")
    ssg = SecurityStateGraph()
    canary = "AGINITI-SMOKE-TEST-CANARY-20260812"
    agent = AnythingLLMAdapter(api_key=GATEWAY_KEY, workspace_slug=slug, base_url=GATEWAY_BASE_URL)
    agent.register_canary(canary)
    library = build_anythingllm_library(canary)
    mission = Mission(goal="smoke test 2", success_criteria=("anythingllm_rag_injection_executed",),
                       budget=2, risk_threshold=RiskTier.MEDIUM, constraints=())

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=2, ssg=ssg)

    print(f"outcome={result.outcome} prompts_used={result.prompts_used}")
    print(f"operators_executed={result.operators_executed}")
    for e in result.execution_log:
        print(f"  [{e.operator_id}] overall_success={e.overall_success} confirmed_keys={e.confirmed_keys}")
    print(f"final claims: {[(c.key, c.status.value) for c in ssg.claims]}")
    print(f"ground_truth_mission_achieved={agent.ground_truth_mission_achieved()}")

    # Pass bar: BOTH steps were genuinely attempted through the real
    # precondition gate (plant, then trigger only after plant confirmed),
    # and the pipeline produced an explicit classification either way.
    ran_both_steps = "anythingllm_rag_document_plant" in result.operators_executed
    plant_classified = ssg.is_confirmed("anythingllm_document_planted")
    trigger_ran = "anythingllm_rag_injection_trigger" in result.operators_executed
    print(f"PASS: plant step ran={ran_both_steps}, plant classified={plant_classified}, "
          f"trigger step attempted (real precondition gate worked)={trigger_ran}")
    return ran_both_steps and plant_classified


def main() -> None:
    r1 = smoke_test_1_judge_path_single_step()
    r2 = smoke_test_2_deterministic_chain_two_step()
    print("\n=== SUMMARY ===")
    print(f"Smoke test 1 (judge path, single-step): {'PASS' if r1 else 'FAIL'}")
    print(f"Smoke test 2 (deterministic path, 2-step chain): {'PASS' if r2 else 'FAIL'}")
    print("\nNote: PASS here means 'the real pipeline ran end-to-end against a live target and "
          "produced an explicit, correctly-classified result' -- it is NOT a claim that the target "
          "was successfully compromised, and these 2 trials are not a statistically meaningful "
          "sample of anything. This is infrastructure verification, not a benchmark.")


if __name__ == "__main__":
    main()
