"""
Zero-arg smoke-test runner for SECRETAttack (jailbreak-optimized DRA) against
the Tier 1 dev fixture (reference_agent_blackbox, port 8001) — the SECRET
parallel of scripts/run_ikea.py / scripts/run_interrogation.py.

**Cost warning, read before running** (see plans/secret-dra-attack.md §1.2
for the full breakdown): SECRET has two separate cost phases. Phase 1
(jailbreak optimization) alone costs roughly
``phase1_n_iter * (1 optimizer call + phase1_n_cand * (1 target query + 1
evaluator call))`` in the worst case, before Phase 2 spends a single query
against the real knowledge base. Phase 2 then adds its own classifier +
semantic-shift LLM calls per query on top of ``max_queries`` target queries.
The constants below are deliberately small (phase1_n_iter=5, phase1_n_cand=2,
max_queries=15) — this is a wiring/correctness smoke test, not a benchmark
run. Increase gradually once this is confirmed working end-to-end.

Not yet folded into scripts/run_benchmark.py's CLI registry, same current
state as scripts/run_interrogation.py — this script exists specifically to
close the "has this ever actually been run against a live agent" gap before
that larger integration is worth doing.

CLI flags (added for the first live-verification pass, 2026-08-12) let you
dial the budget down further than the defaults below without editing the
file — same staged-verification convention established for the hardened
target (run_ikea_hardened.py / run_interrogation_hardened.py):
    python scripts/run_secret.py --phase1-n-iter 3 --phase1-n-cand 2 --queries 5
"""
import argparse
import json
import logging
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(message)s")

from aginiti.attacks.dra import SECRETAttack

_KEY_ENV_VAR = {
    "gemini": "GEMINI_API_KEY",
    "google": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}


def _key_for(model: str) -> str:
    provider = model.split("/", 1)[0].lower()
    env_var = _KEY_ENV_VAR.get(provider)
    if env_var is None:
        raise ValueError(f"No known API key env var for provider {provider!r}")
    key = os.environ.get(env_var)
    if not key:
        raise ValueError(f"{env_var} not set in .env")
    return key


parser = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument("--agent-url", default=os.getenv("IKEA_TARGET_URL", "http://localhost:8001"))
parser.add_argument("--phase1-n-iter", type=int, default=5,
                     help="Phase 1 max optimization iterations (paper default: 20). Default: 5.")
parser.add_argument("--phase1-n-cand", type=int, default=2,
                     help="Phase 1 candidates per iteration (paper default: 3). Default: 2.")
parser.add_argument("--queries", type=int, default=15,
                     help="Phase 2 (CFT) query budget. Default: 15.")
parser.add_argument("--epsilon-local", type=int, default=8,
                     help="LE local query budget before forced GE (paper default: 30). Default: 8.")
parser.add_argument("--le-stagnation-empty-steps", type=int, default=2)
parser.add_argument("--force-refresh-phase1", action="store_true",
                     help="Bypass the cached p_e* (if any) and re-run Phase 1 unconditionally.")
# 2026-08-20 (integration Slice F): the attacker's own completion model
# (Phase 1 optimizer/evaluator + Phase 2 classifier/semantic-shift), was
# hardcoded to gemini/gemini-3.5-flash with no override -- added so a
# Groq run (e.g. --provider groq/openai/gpt-oss-20b) doesn't require
# editing this file. Independent of the target agent's own AGENT_MODEL.
parser.add_argument("--provider", default="gemini/gemini-3.5-flash",
                     help="The attacker's own completion model. Default: %(default)s")
# 2026-08-21 (Slice F live health sweep): SECRETAttack's own
# semantic_shift_llm_provider default (gemini/gemini-3.5-flash,
# independent of --provider above) was never overridden by this script,
# so a --provider groq/... run still tried to call Gemini's API using the
# GROQ_API_KEY looked up for --provider -- a real cross-provider key
# mismatch, not a "key expired" problem (caught live: "API key not
# valid" on a Gemini call while running with --provider groq/...). This
# flag lets it be set explicitly; when omitted it now tracks --provider
# instead of silently defaulting to a different provider than the rest
# of the run, matching run_interrogation.py's --shadow-provider pattern.
parser.add_argument("--semantic-shift-provider", default=None,
                     help="LLM used for Phase 2's semantic-shift fusion calls. "
                          "Default: tracks --provider (was hardcoded to "
                          "gemini/gemini-3.5-flash independent of --provider "
                          "-- fixed 2026-08-21, see comment above).")
args = parser.parse_args()

TARGET_URL = args.agent_url
LLM_PROVIDER = args.provider
SEMANTIC_SHIFT_LLM_PROVIDER = args.semantic_shift_provider or LLM_PROVIDER
DOMAIN = "HR records"

# Deliberately small smoke-test hyperparameters by default — see the module
# docstring's cost warning before scaling any of these up. Override via the
# CLI flags above instead of editing these constants.
PHASE1_N_ITER = args.phase1_n_iter
PHASE1_N_CAND = args.phase1_n_cand
MAX_QUERIES = args.queries
EPSILON_LOCAL = args.epsilon_local
LE_STAGNATION_EMPTY_STEPS = args.le_stagnation_empty_steps

# External Global-Exploration corpus — deliberately generic, NOT related to
# the target's HR domain (matches the paper's own design: Wikipedia is a
# neutral, unrelated natural-text source used only to seed cluster
# discovery; the domain relevance comes from LE's semantic-shift fusion
# once a real seed document is found, not from the corpus itself). Not
# bundled in the library (aginiti-redteam has no Wikipedia-download logic —
# see plans/secret-dra-attack.md §5.2) — a real engagement should supply a
# larger, genuinely diverse corpus than these 15 sentences.
EXTERNAL_CORPUS = [
    "The Eiffel Tower was completed in 1889 for the World's Fair in Paris.",
    "Photosynthesis converts light energy into chemical energy in plants.",
    "The Great Barrier Reef is the world's largest coral reef system.",
    "Shakespeare wrote 39 plays and 154 sonnets during his lifetime.",
    "The speed of light in a vacuum is approximately 299,792 kilometers per second.",
    "Mount Everest is the tallest mountain above sea level on Earth.",
    "The printing press was invented by Johannes Gutenberg around 1440.",
    "Octopuses have three hearts and blue blood.",
    "The Amazon rainforest produces roughly 20% of the world's oxygen.",
    "Ancient Rome's Colosseum could hold an estimated 50,000 spectators.",
    "DNA was first identified by Friedrich Miescher in 1869.",
    "The Sahara is the largest hot desert in the world.",
    "Jazz music originated in New Orleans in the late 19th century.",
    "Honey never spoils if stored properly, archaeologists have found.",
    "The Wright brothers achieved powered flight for the first time in 1903.",
]

attack = SECRETAttack(
    target_url=TARGET_URL,
    llm_provider=LLM_PROVIDER,
    api_key=_key_for(LLM_PROVIDER),
    external_corpus=EXTERNAL_CORPUS,
    phase1_n_iter=PHASE1_N_ITER,
    phase1_n_cand=PHASE1_N_CAND,
    max_queries=MAX_QUERIES,
    epsilon_local=EPSILON_LOCAL,
    le_stagnation_empty_steps=LE_STAGNATION_EMPTY_STEPS,
    # 2026-08-21: pass the correct key for whichever provider is actually
    # used for semantic-shift calls, instead of relying on the base
    # api_key= fallback (which is keyed to LLM_PROVIDER, not
    # SEMANTIC_SHIFT_LLM_PROVIDER -- these can now differ if
    # --semantic-shift-provider is passed explicitly).
    semantic_shift_llm_provider=SEMANTIC_SHIFT_LLM_PROVIDER,
    semantic_shift_api_key=_key_for(SEMANTIC_SHIFT_LLM_PROVIDER),
)

started_at = datetime.now(timezone.utc)
findings = attack.execute(domain=DOMAIN, force_refresh_phase1=args.force_refresh_phase1)
finished_at = datetime.now(timezone.utc)
duration_seconds = (finished_at - started_at).total_seconds()

print("\n" + "=" * 70)
print(f"RESULT: {len(findings)} finding(s) from {attack.queries_sent}/{MAX_QUERIES} queries")
for f in findings:
    print(f"  {f.severity:8s} conf={f.confidence:.2f}  {f.probe_used[:60]}")
    print(f"           {f.leaked_content[:120]}")
print(f"  GE events / LE steps : {attack.ge_events} / {attack.le_steps}")
print(f"  Refused queries      : {len(attack.refused_queries)}")
print(f"  Phase 1 p_e* score   : {attack.jailbreak_artifact.score:.4f} "
      f"({attack.jailbreak_artifact.iterations_used} iteration(s))")
print(f"  duration: {duration_seconds:.1f}s")
print("=" * 70)

_RESULTS_DIR = Path(__file__).parent / "results"
_RESULTS_DIR.mkdir(exist_ok=True)
_run_id = started_at.strftime("%Y%m%dT%H%M%SZ")
_out_path = _RESULTS_DIR / f"secret_smoketest_{_run_id}.json"

report = {
    "run": {
        "attack": "secret",
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": duration_seconds,
        "target_url": TARGET_URL,
        "llm_provider": LLM_PROVIDER,
        "semantic_shift_llm_provider": SEMANTIC_SHIFT_LLM_PROVIDER,
        "domain": DOMAIN,
        "max_queries": MAX_QUERIES,
        "queries_sent": attack.queries_sent,
        "ge_events": attack.ge_events,
        "le_steps": attack.le_steps,
        "finding_count": len(findings),
        "refused_query_count": len(attack.refused_queries),
        "jailbreak_artifact": asdict(attack.jailbreak_artifact) if attack.jailbreak_artifact else None,
    },
    "findings": [asdict(f) for f in findings],
    "refused_queries": attack.refused_queries,
}
_out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
print(f"\nSaved full results to {_out_path}")
