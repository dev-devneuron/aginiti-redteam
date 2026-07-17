import os
import json
import logging
import dataclasses
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()  # picks up API keys from repo-root .env

# Without this, IKEAAttack's internal progress logging (query N/max_queries,
# etc.) is silent by default (standard logging convention — no handler means
# no output). A full run makes dozens of sequential LLM/embedding/HTTP calls
# and can take several minutes; with no output at all that looks identical
# to a hang. This makes progress visible as it happens.
logging.basicConfig(level=logging.INFO, format="%(message)s")

from aginiti.attacks.dra import IKEAAttack
from aginiti.reporting import generate_markdown_report

# IKEAAttack does NOT read AGENT_MODEL/EMBED_MODEL from the environment on its
# own — those env vars are only auto-read by the *reference agents*
# (benchmarks/dev_fixtures/agents/*/agent.py, seed.py). For the attack itself, llm_provider
# and embed_model must be passed explicitly, or IKEAAttack silently falls
# back to its own hardcoded default (gemini/gemini-embedding-001) regardless
# of what .env says. This resolves the correct key for whichever provider
# each of the two model strings below points at, so llm_provider and
# embed_model can independently be any supported provider without editing
# this script again.
_KEY_ENV_VAR = {
    "gemini": "GEMINI_API_KEY",
    "google": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "cohere": "COHERE_API_KEY",
    "voyage": "VOYAGE_API_KEY",
}


def _key_for(model: str):
    provider = model.split("/", 1)[0].lower()
    # Local models (ChromaDB ONNX) need no API key.
    if provider in ("chromadb", "local", "onnx"):
        return None
    env_var = _KEY_ENV_VAR.get(provider)
    if env_var is None:
        raise ValueError(
            f"No known API key env var mapped for provider '{provider}' "
            f"(from model '{model}'). Add it to _KEY_ENV_VAR above."
        )
    key = os.environ.get(env_var)
    if not key:
        raise ValueError(f"{env_var} is not set in .env — required for model '{model}'")
    return key


# The attacker's own completion model (anchor/query generation) — independent
# of the target agent's AGENT_MODEL in .env.
LLM_PROVIDER = "gemini/gemini-3.5-flash"

# The attacker's own embedding model (ERS/TRDM similarity math). Default is now
# local ONNX via ChromaDB — zero embedding API cost, no key needed. Reads
# EMBED_MODEL from .env so switching to a cloud provider (Gemini/OpenAI/Mistral/
# Cohere/Voyage) doesn't require touching this file; a cloud embed model needs
# the matching key set, which _key_for() resolves (local models resolve to None).
EMBED_MODEL = os.getenv("EMBED_MODEL", "chromadb/all-MiniLM-L6-v2")

TARGET_URL = "http://localhost:8001"
TOPIC = "HR records"
MAX_QUERIES = 20   # start small; paper used 256

# theta_inter/n_anchor_candidates overrides — NOT the library defaults (those
# stay at the paper's Table 5 values: theta_inter=0.5, n_anchor_candidates=20).
# _init_anchors' greedy diversity filter drops any candidate whose similarity
# to an already-kept anchor exceeds theta_inter. The paper's defaults assume
# a knowledge base broad enough that 20 LLM-proposed anchor words naturally
# span diverse embedding-space regions. benchmarks/dev_fixtures/datasets/ground_truth.json
# is a single narrow domain (25 HR records, one topic) — most of the 20
# candidates the LLM proposes for "HR records" (e.g. "HRIS", "personnel
# records", "employee data") are near-synonyms that cluster tightly, so the
# strict paper-default filter can collapse the anchor set down to just 1
# survivor. With only 1 anchor, ERS (_er_sample) has nothing else to pick —
# every resample after a TRDM chain ends deterministically returns that same
# anchor, which looks like "the algorithm won't move on" but is really "there
# is only one anchor to choose from." This is a benchmark-dataset-shape
# issue, not a confidence-score bug.
#
# Measured against this exact dataset/topic/embed model (gemini-embedding-001,
# n_anchor_candidates=30) on 2026-07-07:
#   theta_inter=0.50 (library default) -> 1 anchor
#   theta_inter=0.55                   -> 3 anchors
#   theta_inter=0.60                   -> 10 anchors
#   theta_inter=0.65                   -> 21 anchors
# 0.6 is the calibrated sweet spot for this dataset — enough real alternatives
# for ERS to sample between without collapsing to a near-total-pass-through.
# Re-measure if you change EMBED_MODEL, n_anchor_candidates, or the topic.
attack = IKEAAttack(
    target_url=TARGET_URL,
    llm_provider=LLM_PROVIDER,
    api_key=_key_for(LLM_PROVIDER),
    embed_model=EMBED_MODEL,
    embed_api_key=_key_for(EMBED_MODEL),
    topic=TOPIC,
    max_queries=MAX_QUERIES,
    n_anchor_candidates=30,
    theta_inter=0.6,
    # theta_anchor: lower than the paper's default of 0.7. The paper used
    # all-mpnet-base-v2 which produces higher cosine similarities between
    # anchor words and generated questions. all-MiniLM-L6-v2 (our local ONNX
    # default) produces systematically lower scores (~0.4-0.6 range) — at
    # theta_anchor=0.7, every query generation attempt fails (3 retries × 3
    # LLM calls per anchor = infinite LLM burn with 0 probes sent).
    # Re-measure if you change EMBED_MODEL: run with logging.DEBUG to see the
    # "best sim=" values, then set theta_anchor just below the typical max.
    theta_anchor=0.5,
)

started_at = datetime.now(timezone.utc)
findings = attack.execute(topic=TOPIC)
finished_at = datetime.now(timezone.utc)

for f in findings:
    print(f"{f.severity:8s} conf={f.confidence:.2f}  {f.probe_used[:60]}")
    print(f"          {f.leaked_content[:120]}")

# One timestamped file per run in scripts/results/ — never overwritten.
# aginiti/reporting/ (a structured report generator) is still a stub in the
# library; this is just this script's own output, not that module.
# Old runs are never deleted automatically — clean up scripts/results/ by hand.
_RESULTS_DIR = Path(__file__).parent / "results"
_RESULTS_DIR.mkdir(exist_ok=True)
_run_id = started_at.strftime("%Y%m%dT%H%M%SZ")
_out_path = _RESULTS_DIR / f"ikea_run_{_run_id}.json"

report = {
    "run": {
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": (finished_at - started_at).total_seconds(),
        "target_url": TARGET_URL,
        "topic": TOPIC,
        "max_queries": MAX_QUERIES,
        "llm_provider": LLM_PROVIDER,
        "embed_model": EMBED_MODEL,
        "finding_count": len(findings),
    },
    "findings": [dataclasses.asdict(f) for f in findings],
}
with open(_out_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)

_md_path = _out_path.with_suffix(".md")
generate_markdown_report(report, _md_path)

print(f"\nSaved {len(findings)} finding(s) to {_out_path}")
print(f"Markdown report: {_md_path}")
