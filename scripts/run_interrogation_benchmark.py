"""
Large-scale MIA benchmark runner — scores a large LABELED set of member and
non-member documents via ``InterrogationAttack.score_documents`` and
computes the paper's own Table 2 metrics (AUC-ROC, TPR@{0.5%,1%,5%}FPR,
Accuracy@FPR=10%) via ``aginiti.reporting.mia_metrics``.

**Different from ``scripts/run_interrogation_hardened.py``**: that script
tests a handful of candidates against a CALIBRATED threshold — a
per-document membership verdict. This script scores a large labeled set
directly, with NO calibration/threshold step at all, to compute
population-level statistics comparable to the paper's own benchmark
methodology — see ``aginiti/attacks/mia/README.md``'s "Benchmarking
metrics" section for what each figure means and why it needs document
COUNT, not just ``n_probe_questions``, to be meaningful.

Usage:
    python scripts/run_interrogation_benchmark.py --persona support
    python scripts/run_interrogation_benchmark.py --persona legal \
        --n-members 40 --n-non-members 28 --max-doc-chars 16000

**Document availability is source-skewed — check before choosing a scale.**
CFPB (support) has hundreds of short complaints, so 50+50 fits easily even
at the default cap. CUAD (legal) contracts run far longer (median ~36K
chars) — at the default ``--max-doc-chars=8000`` there are only ~33 eligible
members and ~10 eligible non-members, well short of 50+50. This script
fails fast with the exact eligible counts if the requested scale doesn't
fit at the requested cap, rather than silently running a smaller set than
asked for.

Prerequisites: same as run_interrogation_hardened.py —
    python benchmarks/scaled_evals/datasets/prepare_hardened_dataset.py
    python -m benchmarks.scaled_evals.agents.hardened_agent.seed
    uvicorn benchmarks.scaled_evals.agents.hardened_agent.main:app --port 8004
    # + HARDENED_AGENT_{LEGAL,SUPPORT}_API_KEY set in .env
    # optional: GROQ_API_KEY_1..GROQ_API_KEY_N for shadow-LLM key rotation
    #   (see InterrogationAttack's shadow_llm_api_keys docstring) — shadow
    #   call volume (documents x n_probe_questions) dominates at this scale
    #   and is the first thing to hit a single account's rate limit.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(message)s")

from aginiti.attacks.mia import InterrogationAttack  # noqa: E402
from aginiti.reporting.mia_metrics import compute_mia_benchmark_metrics  # noqa: E402

# ---------------------------------------------------------------------------
# Canonical attack-side parameters
# ---------------------------------------------------------------------------
AGENT_URL = os.getenv("HARDENED_AGENT_URL", "http://localhost:8004")
INGESTED_PATH = "benchmarks/scaled_evals/datasets/hardened_dataset_ingested.json"
HELD_OUT_PATH = "benchmarks/scaled_evals/datasets/hardened_dataset_held_out.json"
LLM_PROVIDER = "gemini/gemini-3.5-flash"
SHADOW_LLM_PROVIDER = "groq/llama-3.3-70b-versatile"
DEFAULT_QUERIES = 30  # paper's own headline default -- this IS the paper-comparable run
DEFAULT_N_MEMBERS = 50
DEFAULT_N_NON_MEMBERS = 50
DEFAULT_MAX_DOC_CHARS = 8000  # comfortable for support/CFPB; legal/CUAD needs a manual
                               # override -- see module docstring

PERSONAS = ("legal", "support")
_PERSONA_SOURCE = {"legal": "cuad", "support": "cfpb"}

_RESULTS_DIR = Path(__file__).parent.parent / "benchmarks" / "scaled_evals" / "results"

# InterrogationAttack.__init__ requires a non-empty non_member_reference_docs
# list (it's used by execute_black_box's calibration step). score_documents
# doesn't touch it at all -- this is a harmless placeholder to satisfy the
# constructor, not a real calibration reference set. Flagged here rather
# than silently working around it.
_UNUSED_PLACEHOLDER_REFERENCE_DOC = [
    {"id": "_unused_placeholder", "text": "Not used by score_documents(); satisfies __init__."}
]


def _api_key_for(persona: str) -> str:
    env_var = f"HARDENED_AGENT_{persona.upper()}_API_KEY"
    key = os.environ.get(env_var)
    if not key:
        raise SystemExit(
            f"{env_var} is not set (repo-root .env or shell env). "
            f"See benchmarks/scaled_evals/agents/hardened_agent/README.md."
        )
    return key


def _key_for_llm(model: str) -> str:
    provider = model.split("/", 1)[0].lower()
    env_var = {"gemini": "GEMINI_API_KEY", "groq": "GROQ_API_KEY"}.get(provider)
    if env_var is None:
        raise SystemExit(f"No known API key env var for provider {provider!r}")
    key = os.environ.get(env_var)
    if not key:
        raise SystemExit(f"{env_var} not set in .env")
    return key


def _shadow_api_keys(model: str) -> list[str] | None:
    """Same GROQ_API_KEY_1.. rotation convention as run_interrogation_hardened.py."""
    provider = model.split("/", 1)[0].lower()
    if provider != "groq":
        return None
    keys = []
    i = 1
    while True:
        key = os.environ.get(f"GROQ_API_KEY_{i}")
        if not key:
            break
        keys.append(key)
        i += 1
    return keys or None


def _live_toggle_state(agent_url: str) -> dict:
    try:
        resp = requests.get(f"{agent_url}/config", timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        print(f"WARNING: could not fetch {agent_url}/config ({exc}) -- "
              f"run metadata won't record the target's actual toggle state.")
        return {}


def _toggle_tag(config: dict) -> str:
    if not config:
        return "cfg-unknown"

    def _flag(key: str, short: str) -> str:
        return f"{short}-{'on' if config.get(key) else 'off'}"

    return "_".join([
        _flag("rbac_enabled", "rbac"),
        _flag("rate_limit_enabled", "rl"),
        _flag("redaction_enabled", "rd"),
        _flag("memory_enabled", "mem"),
    ])


def _select_labeled_documents(
    persona: str, max_chars: int, n_members: int, n_non_members: int,
) -> tuple[list[dict], list[dict]]:
    """
    Deterministic (sorted by id), source-scoped selection of TRUE members
    (from the ingested dataset) and TRUE non-members (from the held-out
    dataset). Fails fast with the exact eligible counts if the requested
    scale doesn't fit at the requested --max-doc-chars.
    """
    ingested = json.loads(Path(INGESTED_PATH).read_text(encoding="utf-8"))
    held_out = json.loads(Path(HELD_OUT_PATH).read_text(encoding="utf-8"))
    source = _PERSONA_SOURCE[persona]

    ingested_pool = sorted(
        (d for d in ingested if d["source"] == source and len(d["document_text"]) <= max_chars),
        key=lambda d: d["id"],
    )
    held_out_pool = sorted(
        (d for d in held_out if d["source"] == source and len(d["document_text"]) <= max_chars),
        key=lambda d: d["id"],
    )

    if len(ingested_pool) < n_members or len(held_out_pool) < n_non_members:
        raise SystemExit(
            f"Not enough eligible documents at --max-doc-chars={max_chars} for "
            f"persona={persona!r} (source={source!r}):\n"
            f"  {len(ingested_pool)} member-eligible (need {n_members})\n"
            f"  {len(held_out_pool)} non-member-eligible (need {n_non_members})\n"
            f"Raise --max-doc-chars, lower --n-members/--n-non-members, or pick "
            f"a different persona. See aginiti/attacks/mia/README.md's "
            f"'Benchmarking metrics' section for the length-distribution "
            f"numbers behind this (CUAD/legal documents run far longer than "
            f"CFPB/support ones)."
        )

    return ingested_pool[:n_members], held_out_pool[:n_non_members]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--persona", required=True, choices=PERSONAS)
    parser.add_argument("--n-members", type=int, default=DEFAULT_N_MEMBERS)
    parser.add_argument("--n-non-members", type=int, default=DEFAULT_N_NON_MEMBERS)
    parser.add_argument("--queries", type=int, default=DEFAULT_QUERIES,
                        help=f"n_probe_questions per document (default: {DEFAULT_QUERIES}, "
                             f"the paper's own headline setting).")
    parser.add_argument("--max-doc-chars", type=int, default=DEFAULT_MAX_DOC_CHARS)
    parser.add_argument("--agent-url", default=AGENT_URL)
    args = parser.parse_args()

    api_key = _api_key_for(args.persona)
    endpoint_kwargs = {"headers": {"Authorization": f"Bearer {api_key}"}}

    live_config = _live_toggle_state(args.agent_url)
    toggle_tag = _toggle_tag(live_config)
    if live_config:
        print(f"Target's actual toggle state (via /config): {live_config}")

    members, non_members = _select_labeled_documents(
        args.persona, args.max_doc_chars, args.n_members, args.n_non_members,
    )
    print(
        f"\nSelected {len(members)} true members + {len(non_members)} true "
        f"non-members (source={_PERSONA_SOURCE[args.persona]!r}, "
        f"max_doc_chars={args.max_doc_chars}, n_probe_questions={args.queries})"
    )
    total_docs = len(members) + len(non_members)
    print(
        f"Estimated LLM/HTTP calls: attacker={2 * total_docs}, "
        f"shadow={total_docs * args.queries}, target={total_docs * args.queries}"
    )

    all_docs = (
        [{"id": d["id"], "text": d["document_text"], "_is_member": True} for d in members]
        + [{"id": d["id"], "text": d["document_text"], "_is_member": False} for d in non_members]
    )
    label_by_id = {d["id"]: d["_is_member"] for d in all_docs}

    shadow_keys = _shadow_api_keys(SHADOW_LLM_PROVIDER)
    shadow_key = None
    if shadow_keys:
        print(f"Shadow LLM: rotating across {len(shadow_keys)} GROQ_API_KEY_N keys.")
    else:
        shadow_key = _key_for_llm(SHADOW_LLM_PROVIDER)

    attack = InterrogationAttack(
        target_url=args.agent_url,
        llm_provider=LLM_PROVIDER,
        api_key=_key_for_llm(LLM_PROVIDER),
        non_member_reference_docs=_UNUSED_PLACEHOLDER_REFERENCE_DOC,
        shadow_llm_provider=SHADOW_LLM_PROVIDER,
        shadow_llm_api_key=shadow_key,
        shadow_llm_api_keys=shadow_keys,
        n_probe_questions=args.queries,
        endpoint_kwargs=endpoint_kwargs,
    )

    started_at = datetime.now(timezone.utc)
    
    checkpoint_file = _RESULTS_DIR / f"mia_checkpoint_{args.persona}_{args.queries}q.json"
    scored = []
    already_scored_ids = set()
    total_attacker_calls = 0
    total_shadow_calls = 0
    
    if checkpoint_file.exists():
        try:
            with open(checkpoint_file, "r", encoding="utf-8") as f:
                cp = json.load(f)
                scored = cp.get("scored", [])
                total_attacker_calls = cp.get("attacker_calls", 0)
                total_shadow_calls = cp.get("shadow_calls", 0)
            already_scored_ids = {s["id"] for s in scored}
            print(f"Resuming from checkpoint: loaded {len(scored)} previously scored documents.")
        except Exception as e:
            print(f"Failed to load checkpoint (starting fresh): {e}")
            scored = []
    
    for i, doc in enumerate(all_docs):
        if doc["id"] in already_scored_ids:
            continue
        try:
            res = attack.score_documents([{"id": doc["id"], "text": doc["text"]}])
            if res:
                scored.append(res[0])
                total_attacker_calls += attack._llm_call_count
                total_shadow_calls += attack._shadow_llm_call_count
                with open(checkpoint_file, "w", encoding="utf-8") as f:
                    json.dump({
                        "scored": scored,
                        "attacker_calls": total_attacker_calls,
                        "shadow_calls": total_shadow_calls
                    }, f, indent=2)
        except Exception as e:
            print(f"Error scoring document {doc['id']}: {e}")
            raise
            
    # NOTE (2026-08-14): the checkpoint is deliberately NEVER auto-deleted
    # anywhere in this function. This is the exact same class of bug found
    # and fixed in scripts/run_benchmark.py's IKEA path the same day, after
    # a real incident cost ~6.3 hours of API spend: the checkpoint used to
    # be deleted the instant scoring finished, but metrics computation / the
    # final write below can STILL fail independently, with nothing left to
    # fall back on even though `scored` is sitting right here, fully intact.
    # A leftover checkpoint next to a completed run's output is harmless --
    # the resume check above (`if checkpoint_file.exists()`) would just find
    # every document already in `already_scored_ids` and do nothing new.
    # Clean these up manually if the results/ directory gets cluttered.

    # Restore final totals so the report logic picks them up
    attack._llm_call_count = total_attacker_calls
    attack._shadow_llm_call_count = total_shadow_calls

    finished_at = datetime.now(timezone.utc)
    duration_seconds = (finished_at - started_at).total_seconds()

    for r in scored:
        r["is_member"] = label_by_id[r["id"]]

    # compute_mia_benchmark_metrics() is NOT protected by the scoring loop's
    # own try/except (it runs after scoring has already finished) -- same
    # 2026-08-14 fix as above: never let a metrics failure lose findings
    # that are already safely collected. Fall back to metrics=None plus a
    # recorded metrics_error instead of losing `scored` entirely.
    metrics_error = None
    try:
        metrics = compute_mia_benchmark_metrics(scored)
    except Exception as e:
        metrics_error = f"{type(e).__name__}: {e}"
        metrics = None
        print(f"compute_mia_benchmark_metrics failed: {metrics_error} -- "
              f"writing {len(scored)} scored document(s) WITHOUT metrics rather than losing them.")

    print("\n" + "=" * 70)
    print(f"MIA BENCHMARK ({args.persona}, n_probe_questions={args.queries})")
    if metrics is None:
        # compute_mia_benchmark_metrics() failed -- don't crash the summary
        # print over it (2026-08-14, same fix as above).
        print(f"  {len(scored)} document(s) scored -- metrics computation FAILED, "
              f"see run.metrics_error in the output file.")
    else:
        print(f"  {metrics['n_members']} members, {metrics['n_non_members']} non-members")
        print(f"  AUC-ROC             : {metrics['auc_roc']:.4f}")
        print(f"  TPR@0.5%FPR         : {metrics['tpr_at_fpr_0_5pct']:.4f}")
        print(f"  TPR@1%FPR           : {metrics['tpr_at_fpr_1pct']:.4f}")
        print(f"  TPR@5%FPR           : {metrics['tpr_at_fpr_5pct']:.4f}")
        print(f"  Accuracy@FPR=10%    : {metrics['accuracy_at_fpr10']:.4f}")
        print(f"  FPR granularity     : {metrics['fpr_granularity'] * 100:.2f}% (1/n_non_members)")
    print(f"  duration            : {duration_seconds:.1f}s")
    print(f"  LLM calls -- attacker: {attack._llm_call_count}, shadow: {attack._shadow_llm_call_count}")
    print("=" * 70)

    run_id = started_at.strftime("%Y%m%dT%H%M%SZ")
    output = _RESULTS_DIR / (
        f"mia_benchmark_{args.persona}_{toggle_tag}_{args.queries}q_"
        f"{len(members)}m{len(non_members)}nm_{run_id}.json"
    )
    report = {
        "run": {
            "attack": "mia_interrogation_benchmark",
            "persona": args.persona,
            "target_toggle_state": live_config or "unknown (config fetch failed)",
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": duration_seconds,
            "target_url": args.agent_url,
            "llm_provider": LLM_PROVIDER,
            "shadow_llm_provider": SHADOW_LLM_PROVIDER,
            "shadow_llm_key_rotation_count": len(shadow_keys) if shadow_keys else 1,
            "n_probe_questions": args.queries,
            "max_doc_chars": args.max_doc_chars,
            "n_members": len(members),
            "n_non_members": len(non_members),
            "attacker_llm_calls": attack._llm_call_count,
            "shadow_llm_calls": attack._shadow_llm_call_count,
            "metrics_error": metrics_error,
        },
        "metrics": metrics,
        "scored_documents": scored,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nSaved full results to {output}")


if __name__ == "__main__":
    main()
