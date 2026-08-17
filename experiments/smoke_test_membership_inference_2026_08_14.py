"""SMOKE TEST for aginiti/adaptive/membership_inference.py -- tiny live
run (2 real docs: 1 ingested member + 1 held-out non-member, 4 probes
each), user-approved 2026-08-14, to confirm the real LLM-backed
generate_probes_fn/judge_response_fn work end-to-end against the real
target before anything bigger. Not trying to find anything -- trying to
NOT CRASH and to produce plausible scores (member clearly higher than
non-member would be the ideal, but this is 1 doc each, nowhere near
enough for a real signal -- see the module's own DEFAULT_NUM_PROBES=8
default note about the paper's real n=30)."""
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
logger = logging.getLogger("smoke_test_mia")

sys.path.insert(0, str(Path(__file__).parent.parent))

from aginiti.adapters.hardened_agent_adapter import HardenedAgentAdapter  # noqa: E402
from aginiti.adaptive.membership_inference import run_membership_inference  # noqa: E402
from aginiti.graph.ssg import SecurityStateGraph  # noqa: E402

_DATASETS = Path(__file__).parent.parent / "benchmarks" / "scaled_evals" / "datasets"


def main() -> None:
    ingested = json.loads((_DATASETS / "hardened_dataset_ingested.json").read_text(encoding="utf-8"))
    held_out = json.loads((_DATASETS / "hardened_dataset_held_out.json").read_text(encoding="utf-8"))

    member_doc = next(r for r in ingested if r["source"] == "cuad")
    non_member_doc = next(r for r in held_out if r["source"] == "cuad")
    logger.info("member candidate: %s | non-member candidate: %s", member_doc["id"], non_member_doc["id"])

    api_key = os.environ["HARDENED_AGENT_LEGAL_API_KEY"]
    agent = HardenedAgentAdapter(persona="legal", api_key=api_key)
    ssg = SecurityStateGraph()

    results = {}
    ok = True
    for label, doc in (("member", member_doc), ("non_member", non_member_doc)):
        try:
            result = run_membership_inference(doc, ssg, agent, num_probes=4, seed=42)
            results[label] = {
                "doc_id": result.candidate_doc_id, "score": result.score,
                "correct": result.correct, "wrong": result.wrong, "unknown": result.unknown,
                "queries_used": result.queries_used,
                "trials": [{"question": t.question, "expected": t.expected_answer,
                            "judged": t.judged_answer, "response_preview": t.target_raw_response[:150]}
                           for t in result.trials],
            }
            logger.info("SMOKE [%s]: score=%.3f correct=%d wrong=%d unknown=%d",
                        label, result.score, result.correct, result.wrong, result.unknown)
        except Exception:
            ok = False
            tb = traceback.format_exc()
            logger.error("SMOKE [%s] CRASHED:\n%s", label, tb)
            results[label] = {"crashed": True, "traceback": tb}

    out_path = Path(__file__).parent.parent / "runs_smoke_test_membership_inference_2026_08_14.json"
    out_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    logger.info("=== SMOKE TEST DONE -- results written to %s ===", out_path)
    logger.info("=== OVERALL: %s ===", "ALL PASSED (no crash)" if ok else "AT LEAST ONE CRASHED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
