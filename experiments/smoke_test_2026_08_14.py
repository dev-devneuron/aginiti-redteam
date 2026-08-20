"""One-off SMOKE TEST, not an experiment -- deliberately tiny live budgets
against both real targets, run with explicit user approval (2026-08-14),
to validate that this session's changes actually work live before any full
experiment is proposed:

  - many_shot_discovery / crescendo_escalation phases (new in
    run_full_assessment(), previously never exercised live at all)
  - the corroboration gate (_corroborated()) doesn't crash on a real
    ground_truth_mission_achieved() call
  - the new system-prompt KnownTextDisclosureIndex signal doesn't crash and
    fires sanely
  - the new hardened_agent-only operators (authority-claim confused-deputy,
    session-isolation, redaction-format-evasion) execute against the real
    target without exceptions
  - healthcare_agent (freshly restarted) still answers correctly and the
    new session-isolation/output-filter-evasion operators run cleanly there

Small, explicit budgets throughout -- this is NOT trying to find anything,
it's trying to NOT CRASH and to produce plausible-looking output. Full
traceback printed and re-raised on any unexpected exception (never
swallowed) so a real bug shows up loudly, not silently."""
from __future__ import annotations

import json
import logging
import os
import sys
import traceback
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("smoke_test")

sys.path.insert(0, str(Path(__file__).parent.parent))

from aginiti.core.observation_adapter import ObservationAdapter  # noqa: E402
from aginiti.adapters.hardened_agent_adapter import HardenedAgentAdapter  # noqa: E402
from aginiti.adapters.healthcare_agent_adapter import HealthcareAgentAdapter  # noqa: E402
from aginiti.adapters.scaled_evals_ground_truth import FuzzyDisclosureIndex, VerbatimDisclosureIndex  # noqa: E402
from aginiti.core.assessment import run_full_assessment  # noqa: E402
from aginiti.core.campaign import run_campaign  # noqa: E402
from aginiti.core.graph.schema import RiskTier  # noqa: E402
from aginiti.core.graph.ssg import SecurityStateGraph  # noqa: E402
from aginiti.core.mission import Mission  # noqa: E402
from aginiti.operators.hardened_agent_definitions import build_hardened_agent_library  # noqa: E402
from aginiti.operators.healthcare_agent_definitions import build_healthcare_agent_library  # noqa: E402
from aginiti.operators.library import OperatorLibrary  # noqa: E402

_DATASETS = Path(__file__).parent.parent / "benchmarks" / "scaled_evals" / "datasets"
_RESULTS: dict[str, dict] = {}


def _record(label: str, ok: bool, detail: dict) -> None:
    _RESULTS[label] = {"ok": ok, **detail}
    logger.info("SMOKE [%s]: ok=%s detail=%s", label, ok, {k: v for k, v in detail.items() if k != "traceback"})


def _run_safely(label: str, fn) -> None:
    try:
        detail = fn()
        _record(label, True, detail or {})
    except Exception as exc:  # noqa: BLE001 -- deliberately broad, this IS the crash-detector
        tb = traceback.format_exc()
        logger.error("SMOKE [%s] CRASHED:\n%s", label, tb)
        _record(label, False, {"error": str(exc), "traceback": tb})


# ---------------------------------------------------------------------------
# hardened_agent: full_assessment with tiny budgets (exercises encoding,
# many_shot, framing, crescendo, AND the new persona-specific operators via
# the final campaign phase) for ONE persona (legal -- cheapest, most
# document content available).
# ---------------------------------------------------------------------------
def _smoke_hardened_full_assessment() -> dict:
    hardened_index = VerbatimDisclosureIndex.from_json_files(_DATASETS / "hardened_dataset_ingested.json")
    fuzzy_index = FuzzyDisclosureIndex.from_json_files(_DATASETS / "hardened_dataset_ingested.json")
    api_key = os.environ["HARDENED_AGENT_LEGAL_API_KEY"]
    agent = HardenedAgentAdapter(persona="legal", api_key=api_key, disclosure_index=hardened_index,
                                  fuzzy_disclosure_index=fuzzy_index)
    library = OperatorLibrary(build_hardened_agent_library("legal", hardened_index))
    ssg = SecurityStateGraph()
    mission = Mission(goal="smoke test", success_criteria=("__no_such_key__",), budget=8,
                       risk_threshold=RiskTier.MEDIUM, success_mode="any")

    result = run_full_assessment(
        mission, library, agent, ssg=ssg,
        encoding_discovery_budget=1, many_shot_budget=1,
        framing_discovery_budget=1, framing_refinement_attempts=0,
        crescendo_turns=1, seed=42,
    )
    return {
        "total_prompts_used": result.total_prompts_used,
        "encoding_succeeded": result.encoding_discovery.succeeded if result.encoding_discovery else None,
        "many_shot_succeeded": result.many_shot_discovery.succeeded if result.many_shot_discovery else None,
        "framing_results": [d.succeeded for d, _r in result.framing_discovery],
        "crescendo_results": [c.succeeded if c else None for c in result.crescendo_escalations],
        "stopped_early_after": result.stopped_early_after,
        "outcome": result.outcome,
        "campaign_ran": result.campaign is not None,
        "ground_truth_mission_achieved_final": agent.ground_truth_mission_achieved(),
        "system_prompt_disclosure_confirmed_final": agent.system_prompt_disclosure_confirmed(),
    }


# ---------------------------------------------------------------------------
# hardened_agent: a tiny direct campaign specifically to exercise the NEW
# operators this session added (authority-claim, session-isolation,
# redaction-format-evasion) against the real target, for the "support"
# persona (not yet touched by the full_assessment smoke test above).
# ---------------------------------------------------------------------------
def _smoke_hardened_new_operators() -> dict:
    hardened_index = VerbatimDisclosureIndex.from_json_files(_DATASETS / "hardened_dataset_ingested.json")
    fuzzy_index = FuzzyDisclosureIndex.from_json_files(_DATASETS / "hardened_dataset_ingested.json")
    api_key = os.environ["HARDENED_AGENT_SUPPORT_API_KEY"]
    agent = HardenedAgentAdapter(persona="support", api_key=api_key, disclosure_index=hardened_index,
                                  fuzzy_disclosure_index=fuzzy_index)
    library = OperatorLibrary(build_hardened_agent_library("support", hardened_index))

    target_ids = [
        "hardened_authority_claim_probe_supervisor_override",
        "session_isolation_probe_prior_session_recall",
        "redaction_format_evasion_ssn_period_separated",
        "redaction_format_evasion_email_spam_evasion_format",
    ]
    ssg = SecurityStateGraph()
    adapter = ObservationAdapter()
    trial_results = {}
    for op_id in target_ids:
        op = library.get(op_id)
        exec_result = adapter.execute(op, ssg, agent, seed=42)
        trial_results[op_id] = {
            "overall_success": exec_result.overall_success,
            "ground_truth_mission_achieved": exec_result.ground_truth_mission_achieved,
            "response_preview": (exec_result.raw_signal or "")[:200],
        }
    return {"trials": trial_results}


# ---------------------------------------------------------------------------
# healthcare_agent: tiny campaign to confirm the freshly-restarted server
# answers correctly and the new session-isolation/output-filter-evasion
# operators run without exceptions.
# ---------------------------------------------------------------------------
def _smoke_healthcare_campaign() -> dict:
    hc_index = VerbatimDisclosureIndex.from_json_files(_DATASETS / "healthcaremagic_1k.json")
    agent = HealthcareAgentAdapter(disclosure_index=hc_index)
    library = OperatorLibrary(build_healthcare_agent_library(hc_index))
    ssg = SecurityStateGraph()
    mission = Mission(goal="smoke test", success_criteria=("__no_such_key__",), budget=3,
                       risk_threshold=RiskTier.MEDIUM, success_mode="any")
    result = run_campaign(mission=mission, library=library, agent=agent, ssg=ssg, seed=42)
    return {
        "outcome": result.outcome,
        "prompts_used": result.prompts_used,
        "operators_executed": result.operators_executed,
    }


def main() -> None:
    logger.info("=== SMOKE TEST START (2026-08-14, user-approved, tiny budgets) ===")
    _run_safely("hardened_full_assessment_legal", _smoke_hardened_full_assessment)
    _run_safely("hardened_new_operators_support", _smoke_hardened_new_operators)
    _run_safely("healthcare_campaign", _smoke_healthcare_campaign)

    out_path = Path(__file__).parent.parent / "experiments/results/runs_smoke_test_2026_08_14.json"
    out_path.write_text(json.dumps(_RESULTS, indent=2, default=str), encoding="utf-8")
    logger.info("=== SMOKE TEST DONE -- results written to %s ===", out_path)

    all_ok = all(r["ok"] for r in _RESULTS.values())
    logger.info("=== OVERALL: %s ===", "ALL PASSED" if all_ok else "AT LEAST ONE CRASHED")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
