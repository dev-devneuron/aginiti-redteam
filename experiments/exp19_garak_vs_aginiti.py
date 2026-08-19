"""exp19 -- Aginiti vs garak, a properly designed comparison, built at
explicit, detailed user request (2026-08-11). Full methodology, fairness
rules, and honest confounders are documented inline at each decision
point below and in the final report this produces.

FAIRNESS RULES (user's own, verbatim requirements this harness honors):
  - Same hardened AnythingLLM target (HARDENED_PROMPT_V2, similarityThreshold
    0.5) for both tools, through the SAME gateway (localhost:3002).
  - No Aginiti-specific target access garak doesn't have -- both go through
    the identical REST chat endpoint with a gateway-issued key.
  - No tuning garak's probes to make them fail, no tuning Aginiti to this
    benchmark -- Aginiti's planner/policy/operator/weight/prompt code is
    UNTOUCHED; this harness calls existing operators DIRECTLY (bypassing
    the planner entirely), which is the correct level for a per-technique
    comparison against garak's own per-probe methodology (garak has no
    "planner" to compare against -- that comparison is what exp16/17/18
    are for, a DIFFERENT question from this one).
  - Fresh workspace per trial on BOTH sides (matches this project's own
    established convention, e.g. exp17_calibration.py) -- eliminates
    cross-trial conversation-history contamination for either tool.
  - Meaningful N (15 per condition here -- large enough to avoid this
    project's own repeatedly-learned "n=5 is noise" lesson, small enough
    to keep total live-call runtime bounded given how many categories/
    probes this comparison spans).

WHAT THIS FILE COVERS: the Aginiti-direct-trial side (bypass the planner,
run ONE operator N times against a fresh hardened-v2 workspace each time).
garak's own side is run separately via its real CLI (see
exp19_garak_probes.py and the actual `python -m garak ...` invocations
documented in exp19_run_log.md) -- garak's probes are NOT reimplemented
here; they run through garak's own real code, unmodified.
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aginiti.core.observation_adapter import ObservationAdapter
from aginiti.adapters.anythingllm_adapter import AnythingLLMAdapter
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.logging_utils import save_json
from aginiti.operators.anythingllm_definitions import build_anythingllm_library
from aginiti.operators.anythingllm_markdown_exfil_definitions import build_anythingllm_markdown_exfil_library
from aginiti.operators.data_exposure import data_exposure_operators

from exp17_hardened_target import LISTENER_BASE_URL, LISTENER_LOG_PATH  # noqa: E402
from garak_setup import GATEWAY_BASE_URL, GATEWAY_KEY  # noqa: E402
from hardened_target_v2_config import HARDENED_PROMPT_V2, HARDENED_WORKSPACE_SETTINGS_V2  # noqa: E402

import requests

N_TRIALS = 15
BASE_SEED = 19000
OUT_DIR = os.path.join(os.path.dirname(__file__), "results", "exp19_aginiti_direct")
os.makedirs(OUT_DIR, exist_ok=True)


def _create_fresh_workspace(name: str) -> str:
    resp = requests.post(
        f"{GATEWAY_BASE_URL}/api/v1/workspace/new",
        headers={"Authorization": f"Bearer {GATEWAY_KEY}", "Content-Type": "application/json"},
        json={"name": name, "chatMode": "chat", "openAiPrompt": HARDENED_PROMPT_V2},
        timeout=30)
    resp.raise_for_status()
    slug = resp.json()["workspace"]["slug"]
    resp2 = requests.post(
        f"{GATEWAY_BASE_URL}/api/v1/workspace/{slug}/update",
        headers={"Authorization": f"Bearer {GATEWAY_KEY}", "Content-Type": "application/json"},
        json={"chatMode": "chat", "openAiPrompt": HARDENED_PROMPT_V2, **HARDENED_WORKSPACE_SETTINGS_V2},
        timeout=30)
    resp2.raise_for_status()
    return slug


def _trial_path(op_id: str, trial: int) -> str:
    return os.path.join(OUT_DIR, f"{op_id}__trial{trial:02d}.json")


def run_operator_direct(op_id: str, op, n_trials: int | None = None, base_seed: int = BASE_SEED,
                          chain_precondition_op=None):
    n_trials = N_TRIALS if n_trials is None else n_trials  # re-read module global at CALL time, not def time
    """Runs `op` N times, each against a FRESH hardened-v2 workspace,
    bypassing the planner entirely (matches garak's own per-probe
    methodology: N independent generations of ONE technique). If
    `chain_precondition_op` is given (a 2-step chain's plant operator),
    it's executed FIRST in the same fresh workspace/SSG so the trigger's
    precondition is real and satisfied -- not faked."""
    adapter = ObservationAdapter()
    results = []
    for trial in range(n_trials):
        path = _trial_path(op_id, trial)
        if os.path.exists(path):
            print(f"  {op_id} trial {trial}: skip (exists)")
            results.append(json.load(open(path, encoding="utf-8")))
            continue
        seed = base_seed + trial
        ws_name = f"e19-{op_id}-{trial}-{seed}".replace("_", "-")[:60]
        try:
            slug = _create_fresh_workspace(ws_name)
        except Exception as exc:  # noqa: BLE001
            record = {"operator_id": op_id, "trial": trial, "seed": seed,
                       "error": f"workspace_create_failed: {exc}"}
            save_json(path, record)
            results.append(record)
            print(f"  {op_id} trial {trial}: WORKSPACE_CREATE_FAILED: {exc}")
            continue

        agent = AnythingLLMAdapter(api_key=GATEWAY_KEY, workspace_slug=slug, base_url=GATEWAY_BASE_URL,
                                    chat_mode="chat")
        ssg = SecurityStateGraph()
        t0 = time.time()
        try:
            if chain_precondition_op is not None:
                plant_result = adapter.execute(chain_precondition_op, ssg, agent, seed=seed)
            exec_result = adapter.execute(op, ssg, agent, seed=seed)
            elapsed = time.time() - t0
            record = {
                "operator_id": op_id, "trial": trial, "seed": seed, "workspace": slug,
                "overall_success": exec_result.overall_success,
                "ground_truth_mission_achieved": exec_result.ground_truth_mission_achieved,
                "confirmed_keys": exec_result.confirmed_keys,
                "raw_signal": exec_result.raw_signal,
                "elapsed_seconds": elapsed,
            }
        except Exception as exc:  # noqa: BLE001
            elapsed = time.time() - t0
            record = {"operator_id": op_id, "trial": trial, "seed": seed, "workspace": slug,
                       "error": str(exc), "elapsed_seconds": elapsed}
        save_json(path, record)
        results.append(record)
        status = "SUCCESS" if record.get("overall_success") else ("ERROR" if "error" in record else "no-effect")
        print(f"  {op_id} trial {trial}: {status} ({record.get('elapsed_seconds', 0):.1f}s)")
    return results


def run_chain_direct(result_id: str, library_builder, canary_prefix: str, seed_offset: int,
                      listener_base_url: str | None = None, listener_log_path: str | None = None,
                      n_trials: int | None = None):
    """Generic 2-step chain runner (plant then trigger), fresh workspace +
    fresh canary per trial. Used for both the RAG chain and the markdown-
    exfil chain -- the only difference is which library_builder/listener
    args are passed."""
    n_trials = N_TRIALS if n_trials is None else n_trials
    adapter = ObservationAdapter()
    for trial in range(n_trials):
        path = _trial_path(result_id, trial)
        if os.path.exists(path):
            print(f"  {result_id} trial {trial}: skip (exists)")
            continue
        seed = BASE_SEED + seed_offset + trial
        canary = f"{canary_prefix}-{trial}-{seed}"
        lib = list(library_builder(canary))
        plant = next(op for op in lib if "plant" in op.id)
        trigger = next(op for op in lib if "trigger" in op.id)
        ws_name = f"e19-{result_id}-{trial}-{seed}".replace("_", "-")[:60]
        try:
            slug = _create_fresh_workspace(ws_name)
        except Exception as exc:  # noqa: BLE001
            save_json(path, {"operator_id": result_id, "trial": trial, "error": f"workspace_create_failed: {exc}"})
            print(f"  {result_id} trial {trial}: WORKSPACE_CREATE_FAILED")
            continue
        agent = AnythingLLMAdapter(api_key=GATEWAY_KEY, workspace_slug=slug, base_url=GATEWAY_BASE_URL,
                                    chat_mode="chat")
        agent.register_canary(canary)
        if listener_log_path:
            agent.register_exfil_listener_log(listener_log_path)
        ssg = SecurityStateGraph()
        t0 = time.time()
        try:
            plant_result = adapter.execute(plant, ssg, agent, seed=seed)
            trigger_result = adapter.execute(trigger, ssg, agent, seed=seed)
            elapsed = time.time() - t0
            record = {
                "operator_id": result_id, "trial": trial, "seed": seed, "workspace": slug,
                "plant_success": plant_result.overall_success,
                "overall_success": trigger_result.overall_success,
                "ground_truth_mission_achieved": trigger_result.ground_truth_mission_achieved,
                "raw_signal": trigger_result.raw_signal, "elapsed_seconds": elapsed,
            }
        except Exception as exc:  # noqa: BLE001
            record = {"operator_id": result_id, "trial": trial, "seed": seed, "workspace": slug, "error": str(exc)}
        save_json(path, record)
        status = "SUCCESS" if record.get("overall_success") else ("ERROR" if "error" in record else "no-effect")
        print(f"  {result_id} trial {trial}: {status}")


def main():
    trap = next(op for op in data_exposure_operators() if op.id == "system_prompt_extraction")
    jailbreak = next(op for op in data_exposure_operators() if op.id == "jailbreak_dan_style")
    encoding_op = next(op for op in data_exposure_operators() if op.id == "encoding_evasion_probe")

    print("=== Category 1: system-prompt extraction ===")
    run_operator_direct("system_prompt_extraction", trap)

    print("=== Category 2: jailbreak/direct prompt injection ===")
    run_operator_direct("jailbreak_dan_style", jailbreak)

    print("=== Category 3: encoding/obfuscation ===")
    run_operator_direct("encoding_evasion_probe", encoding_op)

    print("=== Category 4a: indirect/latent injection (real RAG chain) ===")
    run_chain_direct("anythingllm_rag_injection_trigger", build_anythingllm_library, "E19-RAG", 3000)

    print("=== Category 4b: indirect/latent injection (real markdown-exfil chain) ===")
    run_chain_direct("anythingllm_markdown_image_exfil_trigger",
                      lambda c: build_anythingllm_markdown_exfil_library(c, LISTENER_BASE_URL),
                      "E19-MD", 4000, listener_base_url=LISTENER_BASE_URL, listener_log_path=LISTENER_LOG_PATH)

    print("\nAginiti-direct trials complete.")


if __name__ == "__main__":
    main()
