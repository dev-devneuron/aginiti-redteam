"""Phase 2 Slice F live verification (plans/phase2-operator-wrapping.md,
plans/phase2-task-checklist.md) -- the "make sure everything... running as
expected" health check, run with explicit user approval (2026-08-19/21).

Follows the same discipline as experiments/smoke_test_2026_08_14.py: small,
explicit budgets, NOT trying to find anything, trying to NOT CRASH and to
produce plausible-looking output. Exceptions are never silently swallowed --
_run_safely() records and re-surfaces the full traceback.

Three legs, all against the real Docker-hosted reference_agent_blackbox
(port 8001, the Tier 1 dev fixture -- see docker-compose.yml):

  1. SESSION-REUSE CAMPAIGN: a real run_campaign() (AginitiPolicy, the
     actual adaptive planner -- not StaticPolicy) with a mixed library of
     cheap `data_exposure_operators()` prompt-type operators AND the
     wrapped `deep_attack_operators()` IKEA operator, all executed through
     ONE HTTPAgentAdapter wrapping ONE AgentEndpoint. Verifies (a) exactly
     one AgentEndpoint/requests.Session is ever constructed across the
     whole run -- the entire payoff of Slice A/B/D/E -- via a constructor
     spy, not just trusting the design; (b) sane wall-clock time, prompts
     used vs. mission.budget, and the final claim set; (c) the campaign
     genuinely mixes both operator kinds, not just one.

  2. TARGET-DOWN RESILIENCE: the container is stopped deliberately (not a
     race-timed mid-run kill -- see the leg's own docstring for why a
     deterministic before/after split was chosen over a timing-dependent
     kill), then BOTH a cheap prompt-type operator.execute() AND the IKEA
     deep-attack operator.execute() are run against the now-unreachable
     target, confirming ObservationAdapter returns a clean failed
     ExecutionResult (overall_success=False, is_synthetic-backed raw
     signal) for each -- never an unhandled exception. The container is
     always restarted in a `finally`, even if an assertion fails.

  3. TIER 2 (OTEL) STATUS CHECK: not a live test -- aginiti/instrument/ is
     a genuine 1-line-__init__.py stub (verified by direct read, not
     assumed), so there is no real ingester to exercise. This leg just
     records that fact into the results file rather than silently omitting
     Tier 2 from the report, per this project's "no silent failures"
     standard (CLAUDE.md SS6).

IKEA's own query budget is dialed down via IKEA_OPERATOR_MAX_QUERIES
(env var deep_attack_operators.py already reads) to keep this a plumbing
check, not a benchmark run -- see that module's own docstring for the
convention.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import traceback
from pathlib import Path
from unittest.mock import patch

from dotenv import load_dotenv

load_dotenv()

# Must happen BEFORE importing aginiti.operators.deep_attack_operators --
# that module reads this env var at import time (module-level constant),
# not lazily. Small on purpose: this is a wiring/session-reuse check, not
# a benchmark run (mirrors deep_attack_operators.py's own docstring
# convention for _IKEA_MAX_QUERIES).
os.environ.setdefault("IKEA_OPERATOR_MAX_QUERIES", "5")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("slice_f_smoke_test")

sys.path.insert(0, str(Path(__file__).parent.parent))

from aginiti.adapters.http_agent_adapter import HTTPAgentAdapter  # noqa: E402
from aginiti.connectors.endpoint import AgentEndpoint  # noqa: E402
from aginiti.core.campaign import run_campaign  # noqa: E402
from aginiti.core.graph.schema import RiskTier  # noqa: E402
from aginiti.core.graph.ssg import SecurityStateGraph  # noqa: E402
from aginiti.core.mission import Mission  # noqa: E402
from aginiti.core.observation_adapter import ObservationAdapter  # noqa: E402
from aginiti.operators.data_exposure import data_exposure_operators  # noqa: E402
from aginiti.operators.deep_attack_operators import deep_attack_operators  # noqa: E402
from aginiti.operators.library import OperatorLibrary  # noqa: E402

TARGET_URL = os.environ.get("IKEA_TARGET_URL", "http://localhost:8001")
CONTAINER_NAME = "aginiti-redteam-reference_agent_blackbox-1"

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


# ---------------------------------------------------------------------------
# Leg 1: session-reuse campaign (the core Slice F requirement).
# ---------------------------------------------------------------------------
def _leg1_session_reuse_campaign() -> dict:
    endpoint = AgentEndpoint(base_url=TARGET_URL)
    agent = HTTPAgentAdapter(endpoint)

    library = OperatorLibrary([*data_exposure_operators(), *deep_attack_operators()])

    # success_mode="any": either the cheap system_prompt_extraction probe OR
    # the deep IKEA operator satisfying the mission stops the campaign early
    # (stop_on_mission_success=True, the default) -- so a larger budget is
    # what actually forces the planner to keep going long enough to
    # potentially pick BOTH kinds of operator in one run, which is the
    # thing this leg wants to observe. IKEA's declared cost_prompts equals
    # IKEA_OPERATOR_MAX_QUERIES (5, set above) -- budget=15 leaves headroom
    # for 1-2 cheap probes either side of it.
    mission = Mission(
        goal="Phase 2 Slice F live verification",
        success_criteria=("system_prompt_disclosed", "sensitive_data_exfiltrated"),
        budget=15,
        risk_threshold=RiskTier.MEDIUM,
        success_mode="any",
    )
    ssg = SecurityStateGraph()

    real_init = AgentEndpoint.__init__
    construction_count = {"n": 0}

    def _counting_init(self, *args, **kwargs):
        construction_count["n"] += 1
        return real_init(self, *args, **kwargs)

    started = time.monotonic()
    # Patched at the CLASS level (matches test_deep_attack_operators.py's
    # own spy technique) so it also catches any construction INSIDE the
    # IKEA operator's attack_factory, not just the one built explicitly
    # above. The patch is only active for THIS block, i.e. AFTER the one
    # real `endpoint` above was already constructed -- so the correct
    # session-reuse signal is ZERO further constructions while the
    # campaign runs, not one. (First draft of this script asserted `== 1`
    # here, which double-counted the wrong thing -- caught by actually
    # reading the live result rather than trusting the assertion; fixed
    # 2026-08-21 same day, before this script's own first real run was
    # taken as ground truth.) If session-sharing were broken -- i.e. if
    # ikea.py:1581 ignored `self.endpoint` and fell back to building its
    # own -- this count would be >0.
    with patch.object(AgentEndpoint, "__init__", _counting_init):
        result = run_campaign(mission=mission, library=library, agent=agent, ssg=ssg, seed=42)
    duration_seconds = time.monotonic() - started

    operator_kinds_executed = {
        op_id: library.get(op_id).kind for op_id in result.operators_executed
    }

    return {
        "outcome": result.outcome,
        "steps_executed": result.steps_executed,
        "prompts_used": result.prompts_used,
        "mission_budget": mission.budget,
        "operators_executed": result.operators_executed,
        "operator_kinds_executed": operator_kinds_executed,
        "mixed_kinds_observed": len(set(operator_kinds_executed.values())) > 1,
        "agent_endpoint_constructions_during_campaign": construction_count["n"],
        "single_session_confirmed": construction_count["n"] == 0,
        "final_claims": [
            {"key": c.key, "status": c.status.value} for c in result.ssg.claims
        ],
        "duration_seconds": round(duration_seconds, 1),
    }


# ---------------------------------------------------------------------------
# Leg 2: target-down resilience.
#
# Deliberate design choice, flagged explicitly: the design doc's verification
# plan says "manually stall/kill the target mid-run" -- a literal mid-run
# kill is a timing-dependent race (would the kill land during the cheap
# probe, during IKEA's embedding step, during an LLM call?), which makes the
# test flaky and its exact meaning unclear from run to run. This leg
# instead stops the container FIRST, deterministically, then drives both an
# ordinary prompt operator and the deep-attack operator against a
# guaranteed-unreachable target -- a strictly stronger check (100% of the
# call surface sees the target down, not just whichever call happened to be
# in flight at kill time) that still directly answers the design doc's real
# question: does a target failure produce a clean failed step, or a crashed
# campaign?
# ---------------------------------------------------------------------------
def _leg2_target_down_resilience() -> dict:
    subprocess.run(["docker", "stop", CONTAINER_NAME], check=True, capture_output=True, text=True)
    logger.info("Container %s stopped -- target is now unreachable.", CONTAINER_NAME)
    try:
        # Give the stop a moment to actually tear down the listening socket.
        time.sleep(2)

        endpoint = AgentEndpoint(base_url=TARGET_URL)
        agent = HTTPAgentAdapter(endpoint)
        ssg = SecurityStateGraph()
        obs_adapter = ObservationAdapter()

        prompt_library = OperatorLibrary(data_exposure_operators())
        prompt_op = prompt_library.get("system_prompt_extraction")
        prompt_result = obs_adapter.execute(prompt_op, ssg, agent, seed=42)

        deep_op = deep_attack_operators()[0]
        deep_result = obs_adapter.execute(deep_op, ssg, agent, seed=42)

        return {
            "prompt_operator_overall_success": prompt_result.overall_success,
            "prompt_operator_raw_signal_preview": (prompt_result.raw_signal or "")[:160],
            "deep_operator_overall_success": deep_result.overall_success,
            "deep_operator_raw_signal_preview": (deep_result.raw_signal or "")[:200],
            "no_exceptions_raised": True,
        }
    finally:
        subprocess.run(["docker", "start", CONTAINER_NAME], check=True, capture_output=True, text=True)
        logger.info("Container %s restarted.", CONTAINER_NAME)
        # Give the target a moment to come back up before anything else in
        # this process (or a subsequent script run) depends on port 8001.
        time.sleep(3)


# ---------------------------------------------------------------------------
# Leg 3: Tier 2 (OTel) status -- not a live test, an honest status record.
# ---------------------------------------------------------------------------
def _leg3_tier2_otel_status() -> dict:
    instrument_dir = Path(__file__).parent.parent / "aginiti" / "instrument"
    init_file = instrument_dir / "__init__.py"
    contents = init_file.read_text(encoding="utf-8") if init_file.exists() else None
    is_stub = contents is not None and len(contents.strip().splitlines()) <= 3
    return {
        "aginiti_instrument_init_exists": init_file.exists(),
        "aginiti_instrument_init_contents": contents,
        "is_genuine_stub": is_stub,
        "note": (
            "execute_with_traces() is correctly implemented at the attack-logic "
            "level for all 4 attacks (calls execute_black_box() internally, then "
            "would upgrade findings via self.otel.get_retrieval_span_for_query() "
            "if a real ingester existed) -- but aginiti/instrument/ has no real "
            "OTel ingester today, so no live Tier 2 verification is possible. "
            "Recorded here rather than silently omitted from the Slice F report."
        ),
    }


def main() -> None:
    logger.info("=== PHASE 2 SLICE F LIVE VERIFICATION START (2026-08-21) ===")
    _run_safely("session_reuse_campaign", _leg1_session_reuse_campaign)
    _run_safely("target_down_resilience", _leg2_target_down_resilience)
    _run_safely("tier2_otel_status", _leg3_tier2_otel_status)

    out_path = Path(__file__).parent.parent / "experiments/results/runs_smoke_test_2026_08_21_phase2_slice_f.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(_RESULTS, indent=2, default=str), encoding="utf-8")
    logger.info("=== SLICE F VERIFICATION DONE -- results written to %s ===", out_path)

    all_ok = all(r["ok"] for r in _RESULTS.values())
    logger.info("=== OVERALL: %s ===", "ALL PASSED" if all_ok else "AT LEAST ONE CRASHED")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
