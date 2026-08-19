"""Broader SMOKE SWEEP, 2026-08-14, user-approved -- covers everything
added this session that the two earlier smoke tests didn't yet touch live:
  - access_control_layer_probe operators (0 live runs so far) -- both
    hardened_agent (ops persona) and healthcare_agent
  - the 3 redaction_format_evasion variants the first smoke test didn't
    exercise (space-separated SSN, asterisk card, international phone)
  - calibrate_threshold_from_held_out() against 2 real held-out docs
  - session_isolation_probe / access_control_layer_probe against
    healthcare_agent specifically (untested there so far)
Still a SWEEP, not an experiment -- small, fixed, deterministic operator
selection (not planner-driven), just checking every new code path survives
contact with the real targets. No mission/success-criteria scoring."""
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
logger = logging.getLogger("smoke_sweep")

sys.path.insert(0, str(Path(__file__).parent.parent))

from aginiti.adapter.observation_adapter import ObservationAdapter  # noqa: E402
from aginiti.adapters.hardened_agent_adapter import HardenedAgentAdapter  # noqa: E402
from aginiti.adapters.healthcare_agent_adapter import HealthcareAgentAdapter  # noqa: E402
from aginiti.adapters.scaled_evals_ground_truth import FuzzyDisclosureIndex, VerbatimDisclosureIndex  # noqa: E402
from aginiti.adaptive.membership_inference import calibrate_threshold_from_held_out  # noqa: E402
from aginiti.graph.ssg import SecurityStateGraph  # noqa: E402
from aginiti.operators.hardened_agent_definitions import build_hardened_agent_library  # noqa: E402
from aginiti.operators.healthcare_agent_definitions import build_healthcare_agent_library  # noqa: E402
from aginiti.operators.library import OperatorLibrary  # noqa: E402

_DATASETS = Path(__file__).parent.parent / "benchmarks" / "scaled_evals" / "datasets"
_RESULTS: dict[str, dict] = {}


def _record(label: str, ok: bool, detail: dict) -> None:
    _RESULTS[label] = {"ok": ok, **detail}
    logger.info("SWEEP [%s]: ok=%s detail=%s", label, ok, {k: v for k, v in detail.items() if k != "traceback"})


def _run_safely(label: str, fn) -> None:
    try:
        detail = fn()
        _record(label, True, detail or {})
    except Exception as exc:  # noqa: BLE001
        tb = traceback.format_exc()
        logger.error("SWEEP [%s] CRASHED:\n%s", label, tb)
        _record(label, False, {"error": str(exc), "traceback": tb})


def _execute_ids(agent, library, op_ids, seed=42) -> dict:
    ssg = SecurityStateGraph()
    adapter = ObservationAdapter()
    out = {}
    for op_id in op_ids:
        op = library.get(op_id)
        r = adapter.execute(op, ssg, agent, seed=seed)
        out[op_id] = {"overall_success": r.overall_success, "preview": (r.raw_signal or "")[:150]}
    return out


def _sweep_hardened_ops_access_control_and_authority() -> dict:
    hardened_index = VerbatimDisclosureIndex.from_json_files(_DATASETS / "hardened_dataset_ingested.json")
    fuzzy_index = FuzzyDisclosureIndex.from_json_files(_DATASETS / "hardened_dataset_ingested.json")
    agent = HardenedAgentAdapter(persona="ops", api_key=os.environ["HARDENED_AGENT_OPS_API_KEY"],
                                  disclosure_index=hardened_index, fuzzy_disclosure_index=fuzzy_index)
    library = OperatorLibrary(build_hardened_agent_library("ops", hardened_index))
    ids = ["access_control_layer_probe_completeness_count", "access_control_layer_probe_withheld_category"]
    return {"trials": _execute_ids(agent, library, ids)}


def _sweep_hardened_legal_remaining_redaction_variants() -> dict:
    hardened_index = VerbatimDisclosureIndex.from_json_files(_DATASETS / "hardened_dataset_ingested.json")
    agent = HardenedAgentAdapter(persona="legal", api_key=os.environ["HARDENED_AGENT_LEGAL_API_KEY"],
                                  disclosure_index=hardened_index)
    library = OperatorLibrary(build_hardened_agent_library("legal", hardened_index))
    ids = ["redaction_format_evasion_ssn_space_separated", "redaction_format_evasion_credit_card_asterisk_separated",
           "redaction_format_evasion_phone_international_format"]
    return {"trials": _execute_ids(agent, library, ids)}


def _sweep_hardened_legal_calibrate_threshold() -> dict:
    held_out = json.loads((_DATASETS / "hardened_dataset_held_out.json").read_text(encoding="utf-8"))
    candidates = [r for r in held_out if r["source"] == "cuad"][1:3]  # different docs than the MIA smoke test used
    agent = HardenedAgentAdapter(persona="legal", api_key=os.environ["HARDENED_AGENT_LEGAL_API_KEY"])
    ssg = SecurityStateGraph()
    results = calibrate_threshold_from_held_out(candidates, ssg, agent, num_probes=3, seed=42)
    return {"scores": [{"doc_id": r.candidate_doc_id, "score": r.score,
                         "correct": r.correct, "wrong": r.wrong, "unknown": r.unknown} for r in results]}


def _sweep_healthcare_new_operators() -> dict:
    hc_index = VerbatimDisclosureIndex.from_json_files(_DATASETS / "healthcaremagic_1k.json")
    agent = HealthcareAgentAdapter(disclosure_index=hc_index)
    library = OperatorLibrary(build_healthcare_agent_library(hc_index))
    ids = ["access_control_layer_probe_contrast_check", "session_isolation_probe_concurrent_other_user"]
    return {"trials": _execute_ids(agent, library, ids)}


def main() -> None:
    logger.info("=== SMOKE SWEEP START (2026-08-14, user-approved) ===")
    _run_safely("hardened_ops_access_control_and_authority", _sweep_hardened_ops_access_control_and_authority)
    _run_safely("hardened_legal_remaining_redaction_variants", _sweep_hardened_legal_remaining_redaction_variants)
    _run_safely("hardened_legal_calibrate_threshold", _sweep_hardened_legal_calibrate_threshold)
    _run_safely("healthcare_new_operators", _sweep_healthcare_new_operators)

    out_path = Path(__file__).parent.parent / "runs_smoke_sweep_2026_08_14.json"
    out_path.write_text(json.dumps(_RESULTS, indent=2, default=str), encoding="utf-8")
    logger.info("=== SWEEP DONE -- results written to %s ===", out_path)
    all_ok = all(r["ok"] for r in _RESULTS.values())
    logger.info("=== OVERALL: %s ===", "ALL PASSED" if all_ok else "AT LEAST ONE CRASHED")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
