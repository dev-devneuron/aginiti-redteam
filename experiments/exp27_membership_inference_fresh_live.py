"""exp27 -- the corrected membership-inference run, fixing the exact design
flaw exp26 exposed: running M_membership_inference AFTER A_baseline +
E_full_assessment for the same persona/bearer key meant every MI check ran
against a conversation state already primed by ~60 prior turns, and
hardened_agent's own memory-caution system-prompt suffix ("if you've
already disclosed several distinct things, be more cautious") made the
model uniformly answer "unknown" regardless of TRUE membership -- all 6
exp26 MI checks (3 personas x member+non-member) came back an identical,
signal-free -0.5.

THE FIX: this script does ONLY membership inference, run FIRST (in its own
separate process, against a server restarted immediately before this run
started -- confirmed via the restart timestamp, not assumed) -- for each
persona, its member/non-member check is the very FIRST query that
persona's bearer key has ever sent since the server came up. No other
operator, no baseline campaign, no full_assessment phase touches these
personas' conversation state before or during this run.

Also uses DEFAULT_NUM_PROBES=8 (the module's own default, double exp26's
n=4) for a somewhat firmer signal now that the mechanism itself is already
proven working -- real cost tradeoff, not free, but affordable at this
scope (8 probes x 2 docs x 3 personas = 48 candidate-document checks, each
2 LLM calls = up to 96 calls total).

Usage:
    python experiments/exp27_membership_inference_fresh_live.py
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, ".")

from dotenv import load_dotenv

load_dotenv()

import requests

from aginiti.adapters.hardened_agent_adapter import HardenedAgentAdapter
from aginiti.adaptive.membership_inference import DEFAULT_NUM_PROBES, run_membership_inference
from aginiti.core.graph.ssg import SecurityStateGraph

_ROOT = Path(__file__).parent.parent
_DATASETS = _ROOT / "benchmarks" / "scaled_evals" / "datasets"
_RESULTS_DIR = _ROOT / "experiments/results/runs_exp27_membership_inference_fresh"
_RESULTS_DIR.mkdir(exist_ok=True)

_PERSONAS = ("legal", "support", "ops")
_TIMEOUT = 180.0
_NUM_PROBES = DEFAULT_NUM_PROBES  # 8 -- see module docstring
_SOURCE_BY_PERSONA = {"legal": "cuad", "support": "cfpb", "ops": "cuad"}
# 2026-08-14 fix: the FIRST run of this script picked the first ingested
# cuad doc for ops's "member" candidate (cuad_0077) WITHOUT checking
# ops_visible -- cuad_0077 turned out to be ops_visible=False, i.e. a real
# ingested document but one OUTSIDE ops's own authorized retrieval scope.
# ops correctly scored it identically to the genuine non-member (both
# -0.500, all "unknown") -- not a membership-inference failure, a candidate-
# selection bug: that result correctly reflects ops's own RBAC scope, not
# whether the document exists in the corpus at all. ops's "member" doc must
# be ops_visible=True to be a valid test of "can ops recognize a document
# it's actually authorized to see."


def _configure_logging() -> None:
    fmt = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(_RESULTS_DIR / "exp27_run.log", mode="a", encoding="utf-8")
    file_handler.setFormatter(fmt)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    aginiti_logger = logging.getLogger("aginiti")
    aginiti_logger.setLevel(logging.INFO)
    aginiti_logger.addHandler(file_handler)
    aginiti_logger.addHandler(console_handler)


def _confirm_server_is_fresh() -> None:
    """A real check, not an assumption: confirms the server is up AND
    logs the current time next to it, so a human reviewing the run log can
    independently verify how close 'restarted before this run' really was
    -- this project's own 'don't assume, verify' discipline."""
    resp = requests.get("http://localhost:8004/config", timeout=10)
    resp.raise_for_status()
    print(f"Server confirmed up at {time.strftime('%Y-%m-%d %H:%M:%S')}: {resp.json()}")
    print("NOTE: this script assumes the caller restarted hardened_agent immediately "
          "before running this -- it cannot itself verify server UPTIME (no such endpoint "
          "exists), only that it's currently reachable. See the session transcript's own "
          "restart timestamp for the actual guarantee.")


def _run_persona_check(persona: str) -> dict:
    label = f"hardened_agent_{persona}__M_membership_inference_fresh"
    print(f"\n{'=' * 78}\n{label}\n{'=' * 78}")
    source = _SOURCE_BY_PERSONA[persona]
    ingested = json.loads((_DATASETS / "hardened_dataset_ingested.json").read_text(encoding="utf-8"))
    held_out = json.loads((_DATASETS / "hardened_dataset_held_out.json").read_text(encoding="utf-8"))
    if persona == "ops":
        # Must be ops_visible=True -- see the module-level comment on
        # _SOURCE_BY_PERSONA for why a plain source-match isn't enough here.
        member_doc = next(r for r in ingested if r["source"] == source and r["ops_visible"])
    else:
        member_doc = next(r for r in ingested if r["source"] == source)
    non_member_doc = next(r for r in held_out if r["source"] == source)

    api_key = os.environ[f"HARDENED_AGENT_{persona.upper()}_API_KEY"]
    # A FRESH adapter instance -- but note (see module docstring) this does
    # NOT by itself guarantee a fresh SERVER-SIDE conversation state, since
    # memory is keyed by persona string on the server, not by client
    # instance. What actually makes this fresh is that NOTHING else has
    # queried this persona's key since the server restart -- true here
    # because this script runs nothing else.
    adapter = HardenedAgentAdapter(persona=persona, api_key=api_key, timeout=_TIMEOUT)
    ssg = SecurityStateGraph()

    member_result = run_membership_inference(member_doc, ssg, adapter, num_probes=_NUM_PROBES, seed=42)
    non_member_result = run_membership_inference(non_member_doc, ssg, adapter, num_probes=_NUM_PROBES, seed=42)
    print(f"member({member_doc['id']}): score={member_result.score:.3f} "
          f"(correct={member_result.correct} wrong={member_result.wrong} unknown={member_result.unknown})")
    print(f"non_member({non_member_doc['id']}): score={non_member_result.score:.3f} "
          f"(correct={non_member_result.correct} wrong={non_member_result.wrong} unknown={non_member_result.unknown})")

    record = {
        "persona": persona, "status": "completed",
        "member": {"doc_id": member_result.candidate_doc_id, "score": member_result.score,
                   "correct": member_result.correct, "wrong": member_result.wrong, "unknown": member_result.unknown,
                   "trials": [asdict(t) for t in member_result.trials]},
        "non_member": {"doc_id": non_member_result.candidate_doc_id, "score": non_member_result.score,
                        "correct": non_member_result.correct, "wrong": non_member_result.wrong,
                        "unknown": non_member_result.unknown, "trials": [asdict(t) for t in non_member_result.trials]},
        "score_gap": member_result.score - non_member_result.score,
    }
    (_RESULTS_DIR / f"{label}.json").write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    return record


def main() -> None:
    _configure_logging()
    _confirm_server_is_fresh()

    # Optional: python exp27_....py ops -- rerun just the listed personas
    # (used 2026-08-14 to redo ONLY ops after the candidate-selection fix,
    # without re-spending budget on legal/support's already-good data).
    personas = tuple(sys.argv[1:]) if len(sys.argv) > 1 else _PERSONAS
    for p in personas:
        if p not in _PERSONAS:
            raise SystemExit(f"unknown persona {p!r}, expected one of {_PERSONAS}")

    # Merge into any existing summary (keyed by persona) rather than
    # clobbering it -- lets a selective rerun (see above) update just the
    # listed personas' rows while preserving already-good ones untouched.
    summary_path = _RESULTS_DIR / "exp27_summary.json"
    existing = {r["persona"]: r for r in json.loads(summary_path.read_text(encoding="utf-8"))} \
        if summary_path.exists() else {}

    for persona in personas:
        try:
            existing[persona] = _run_persona_check(persona)
        except Exception as e:  # noqa: BLE001
            tb = traceback.format_exc()
            print(f"\n{'!' * 78}\n{persona} FAILED: {type(e).__name__}: {e}\n{'!' * 78}\n{tb}")
            (_RESULTS_DIR / f"hardened_agent_{persona}__M_ERROR.txt").write_text(tb, encoding="utf-8")
            existing[persona] = {"persona": persona, "status": "failed",
                                  "error_type": type(e).__name__, "error_message": str(e)}
        summary_path.write_text(json.dumps(list(existing.values()), indent=2), encoding="utf-8")

    rows = list(existing.values())

    print(f"\n{'=' * 78}\nSUMMARY\n{'=' * 78}")
    for r in rows:
        if r.get("status") == "failed":
            print(f"{r['persona']:<10} FAILED: {r.get('error_type')}: {r.get('error_message')}")
            continue
        print(f"{r['persona']:<10} member_score={r['member']['score']:.3f}  "
              f"non_member_score={r['non_member']['score']:.3f}  gap={r['score_gap']:.3f}")
    print(f"\nWritten: {_RESULTS_DIR / 'exp27_summary.json'}")
    print(f"Full log: {_RESULTS_DIR / 'exp27_run.log'}")


if __name__ == "__main__":
    main()
