"""Phase 2 Slice G live verification (plans/phase2-operator-wrapping.md,
plans/phase2-task-checklist.md) -- confirms the 3 newly-wrapped deep-attack
Operators (SECRET, Interrogation/MIA, SPE-LLM) actually run against the
real Docker-hosted reference_agent_blackbox (port 8001), through the real
run_campaign() path, not just mocked unit/integration tests. Same
discipline as experiments/smoke_test_2026_08_21_phase2_slice_f.py: small,
explicit budgets, NOT trying to find anything, trying to NOT CRASH and to
produce plausible-looking output.

IKEA is NOT re-run here -- it was already live-verified in Slice E/F
(runs_smoke_test_2026_08_21_phase2_slice_f.json). This file covers only
the 3 attacks Slice G newly wrapped.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Small, explicit budgets for a live plumbing check -- see each attack's
# own module-level defaults in deep_attack_operators.py for what a real
# (larger) run looks like.
os.environ.setdefault("SECRET_OPERATOR_MAX_QUERIES", "2")
os.environ.setdefault("SECRET_OPERATOR_PHASE1_N_ITER", "2")
os.environ.setdefault("SECRET_OPERATOR_PHASE1_N_CAND", "2")
os.environ.setdefault("MIA_OPERATOR_N_PROBE_QUESTIONS", "2")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("slice_g_smoke_test")

sys.path.insert(0, str(Path(__file__).parent.parent))

from aginiti.adapters.http_agent_adapter import HTTPAgentAdapter  # noqa: E402
from aginiti.connectors.endpoint import AgentEndpoint  # noqa: E402
from aginiti.core.campaign import run_campaign  # noqa: E402
from aginiti.core.graph.schema import RiskTier  # noqa: E402
from aginiti.core.graph.ssg import SecurityStateGraph  # noqa: E402
from aginiti.core.mission import Mission  # noqa: E402
from aginiti.core.policies.static_policy import StaticPolicy  # noqa: E402
from aginiti.operators.deep_attack_operators import deep_attack_operators  # noqa: E402
from aginiti.operators.library import OperatorLibrary  # noqa: E402

TARGET_URL = os.environ.get("IKEA_TARGET_URL", "http://localhost:8001")

_RESULTS: dict[str, dict] = {}


def _record(label: str, ok: bool, detail: dict) -> None:
    _RESULTS[label] = {"ok": ok, **detail}
    logger.info("SMOKE [%s]: ok=%s detail=%s", label, ok,
                {k: v for k, v in detail.items() if k != "traceback"})


def _run_safely(label: str, fn) -> None:
    try:
        detail = fn()
        _record(label, True, detail or {})
    except Exception as exc:  # noqa: BLE001 -- deliberately broad, this IS the crash-detector
        tb = traceback.format_exc()
        logger.error("SMOKE [%s] CRASHED:\n%s", label, tb)
        _record(label, False, {"error": str(exc), "traceback": tb})


def _run_one_operator(operator_id: str) -> dict:
    ops = {op.id: op for op in deep_attack_operators()}
    op = ops[operator_id]
    library = OperatorLibrary([op])
    mission = Mission(
        goal=f"Slice G live check: {operator_id}",
        success_criteria=(op.claim_key,),
        budget=op.cost_prompts,
        risk_threshold=RiskTier.MEDIUM,
        success_mode="any",
    )
    endpoint = AgentEndpoint(base_url=TARGET_URL)
    agent = HTTPAgentAdapter(endpoint)
    ssg = SecurityStateGraph()

    started = time.monotonic()
    result = run_campaign(
        mission=mission, library=library, agent=agent, ssg=ssg,
        policy=StaticPolicy(), max_steps=1, seed=42,
    )
    duration_seconds = time.monotonic() - started

    exec_result = result.execution_log[0] if result.execution_log else None
    claim = result.ssg.current_claim(op.claim_key)
    return {
        "operator_id": operator_id,
        "outcome": result.outcome,
        "prompts_used": result.prompts_used,
        "overall_success": exec_result.overall_success if exec_result else None,
        "reasoning_preview": (exec_result.reasoning or "")[:200] if exec_result else None,
        "claim_status": claim.status.value if claim else None,
        "duration_seconds": round(duration_seconds, 1),
    }


def main() -> None:
    logger.info("=== PHASE 2 SLICE G LIVE VERIFICATION START (2026-08-21) ===")
    _run_safely("secret_jailbreak_exfiltration", lambda: _run_one_operator("secret_jailbreak_exfiltration"))
    _run_safely("mia_membership_inference", lambda: _run_one_operator("mia_membership_inference"))
    _run_safely("spe_system_prompt_extraction", lambda: _run_one_operator("spe_system_prompt_extraction"))

    out_path = Path(__file__).parent.parent / "experiments/results/runs_smoke_test_2026_08_21_phase2_slice_g.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(_RESULTS, indent=2, default=str), encoding="utf-8")
    logger.info("=== SLICE G VERIFICATION DONE -- results written to %s ===", out_path)

    all_ok = all(r["ok"] for r in _RESULTS.values())
    logger.info("=== OVERALL: %s ===", "ALL PASSED" if all_ok else "AT LEAST ONE CRASHED")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
