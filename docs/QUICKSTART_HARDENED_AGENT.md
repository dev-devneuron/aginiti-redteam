# Quickstart — Running a Full Aginiti Experiment Against `hardened_agent`

_Written 2026-08-14. Every command below was actually run, in this order,
in this environment, this session — not assumed or copied from a stale
doc. Where an existing docstring's instructions turned out not to work
(`prepare_hardened_dataset.py`'s own `pip install -e ".[benchmarks]"` line
— this repo has no `pyproject.toml`, so that command fails), this guide
uses what's actually verified instead of repeating it._

This walks through: installing what's needed, starting `hardened_agent`
(the real RBAC'd RAG target), and running Aginiti against it end-to-end —
from a quick sanity check up to the full multi-phase live assessment.

---

## 0. What you're setting up

Two separate things, both needed:

- **`hardened_agent`** — the TARGET. A real RAG chatbot (real CUAD legal
  contracts + CFPB consumer complaints) with real RBAC (3 personas: legal,
  support, ops), redaction, rate limiting, and conversation memory. Runs
  as its own local server on port 8004.
- **Aginiti** — the ATTACKER/tester. Runs as a Python script against
  whatever `hardened_agent`'s URL is.

They're independent processes. `hardened_agent` needs to be up and healthy
before you point Aginiti at it.

## 1. Prerequisites

- Python 3.13 (this session used 3.13.6; anything 3.11+ should work).
- A virtual environment — this guide assumes `.venv` at the repo root,
  activated for every command below (or use the full
  `.venv/Scripts/python.exe` / `.venv/bin/python` path, as this guide
  does, if you don't want to activate).
- Two sets of API keys:
  1. **`GEMINI_API_KEY`** — `hardened_agent` itself calls Gemini
     (`gemini/gemini-3.5-flash` via `litellm`) to generate its RAG
     answers. Without this, the target can't answer anything.
  2. **`GROQ_API_KEY`** — Aginiti's own reasoning (the judge, the
     adaptive-discovery LLM calls, membership-inference probe generation)
     runs on Groq. Falls back to Gemini automatically if the Groq pool is
     exhausted (`aginiti/llm_client.py`), but you need at least one of the
     two working.
  3. Three bearer keys of your own choosing (any string — these
     authenticate CALLERS to `hardened_agent`, not a third-party service):
     `HARDENED_AGENT_LEGAL_API_KEY`, `HARDENED_AGENT_SUPPORT_API_KEY`,
     `HARDENED_AGENT_OPS_API_KEY`.

## 2. Install dependencies

The core Aginiti dependencies:

```bash
.venv/Scripts/python.exe -m pip install -r requirements.txt
```

`hardened_agent` itself needs a second set NOT currently tracked in
`requirements.txt` (a real, honest gap — this guide works around it rather
than hiding it). These exact versions are the ones actually verified
working together in this session:

```bash
.venv/Scripts/python.exe -m pip install chromadb==1.5.9 fastapi==0.141.1 uvicorn==0.52.1 litellm==1.96.2 datasets==3.6.0 onnxruntime==1.28.0 tokenizers==0.22.2 numpy==2.5.1
```

## 3. Configure `.env`

Create (or edit) `.env` at the repo root:

```bash
GEMINI_API_KEY=your-gemini-key-here
GROQ_API_KEY=your-groq-key-here

HARDENED_AGENT_LEGAL_API_KEY=choose-any-string-legal
HARDENED_AGENT_SUPPORT_API_KEY=choose-any-string-support
HARDENED_AGENT_OPS_API_KEY=choose-any-string-ops

# onnx = free, local, no per-chunk API cost (recommended default -- see
# .env's own comment history for why this project deliberately doesn't
# default to Gemini embeddings). Only change this if you know you want
# Gemini-backed embeddings specifically.
SCALED_EVALS_EMBED_BACKEND=onnx
```

## 4. Prepare and seed the dataset

One-time (or whenever you want to rebuild the corpus):

```bash
.venv/Scripts/python.exe benchmarks/scaled_evals/datasets/prepare_hardened_dataset.py
.venv/Scripts/python.exe -m benchmarks.scaled_evals.agents.hardened_agent.seed
```

The first command downloads real CUAD contracts (HuggingFace) and fetches
real CFPB complaints (CFPB's own public API) — takes a minute or two. The
second embeds and indexes them into a local ChromaDB collection using
whichever `SCALED_EVALS_EMBED_BACKEND` you set above. If you ever change
that setting AFTER already seeding once, you must re-seed with `--force`
(`-m benchmarks.scaled_evals.agents.hardened_agent.seed --force`) — the
embedding function is baked into the collection at seed time, and a
mismatch between the two produces a hard `ChromaDB Embedding function
conflict` error at server startup, or a live `InvalidArgumentError:
Collection expecting embedding with dimension of X, got Y` on every
`/chat` call otherwise (both are things this project's own live testing
has hit and fixed — see `docs/EXP26_RESULTS.md`'s bugs-found list).

## 5. Start the `hardened_agent` server

```bash
.venv/Scripts/python.exe -m uvicorn benchmarks.scaled_evals.agents.hardened_agent.main:app --port 8004
```

Run this in its own terminal (or background it — see below) and leave it
running for the rest of this guide.

**Verify it's up and check its actual defense configuration:**

```bash
curl http://localhost:8004/health
curl http://localhost:8004/config
```

The second should return all five defenses `true`:
`{"rbac_enabled":true,"rate_limit_enabled":true,"redaction_enabled":true,"memory_enabled":true,"guardrail_enabled":true}`

**A real gotcha worth knowing before you hit it**: `hardened_agent`'s
conversation memory is scoped per PERSONA for the life of the SERVER
PROCESS, not per script run — if you run several experiments back to back
against the same server without restarting it, later runs silently
inherit earlier runs' conversation history for the same persona. This
genuinely contaminated a real experiment this session (`docs/
EXP26_RESULTS.md`'s membership-inference section). **Restart the server
between independent experiments** if you want a clean baseline:

```bash
# find and stop it
# (Windows) Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%hardened_agent.main%' AND Name='python.exe'" | Select ProcessId
# then Stop-Process -Id <pid> -Force
# then just re-run the uvicorn command from step 5 above
```

## 6. Sanity-check before spending real budget

Confirm the target actually answers before running anything bigger:

```bash
curl -X POST http://localhost:8004/chat -H "Content-Type: application/json" -H "Authorization: Bearer your-legal-key" -d "{\"message\": \"What are typical termination clauses in commercial contracts?\"}"
```

You should get back a real, substantive answer grounded in the seeded
CUAD documents. If you get a 500, re-check step 4's embedding-backend
match.

## 7. Run a full end-to-end experiment

This is the real thing: baseline campaign vs. the full adaptive-discovery
pipeline (encoding, many-shot, framing + refinement, Crescendo escalation,
final planner campaign) vs. membership inference — across all 3 personas.

```bash
.venv/Scripts/python.exe experiments/exp26_full_assessment_v2_live.py
```

This makes real, live LLM calls against both `hardened_agent` and Groq/
Gemini (Aginiti's own reasoning) — real cost, real time (roughly 1-2 hours
at the budgets that script is currently configured with). Read
`experiments/exp26_full_assessment_v2_live.py`'s own module docstring
first — it states the exact experimental design (budgets, personas,
conditions) up front, the same discipline every live experiment in this
project follows. Adjust `_BUDGET`/`_ENCODING_BUDGET`/etc. at the top of
the file if you want a smaller/cheaper/faster run — smaller budgets are
fine for a first look, just expect less of the discovery pipeline to
actually complete before it runs out.

**Prefer a much smaller, faster check first?** Run just the membership-
inference technique on its own — cheaper, faster, and it's the one
mechanism that specifically needs a freshly-restarted server (step 5's
gotcha) to get a clean signal:

```bash
# restart the server (step 5) immediately before this, so each persona's
# check is the first thing that persona's key has ever asked
.venv/Scripts/python.exe experiments/exp27_membership_inference_fresh_live.py
```

## 8. Where results go

Every experiment script writes to its own `runs_<name>/` directory at the
repo root — nothing is only printed to the console:

- `runs_exp26_full_assessment_v2/exp26_summary.json` — one row per
  (persona, condition), the outcome, ground-truth signals, RBAC-crossing
  status.
- `runs_exp26_full_assessment_v2/*_discovery_trials.json` — every
  individual trial's actual prompt and response, not just booleans.
- `runs_exp26_full_assessment_v2/*_ssg.json` — the full
  SecurityStateGraph (every claim, every taxonomy tag) for that run.
- `runs_exp26_full_assessment_v2/exp26_run.log` — every logged event
  (campaign starts/finishes, confirmed findings, corroboration-gate
  activity) in order, with timestamps.
- `runs_exp27_membership_inference_fresh/exp27_summary.json` — per-persona
  member/non-member scores and the gap between them.

For a worked example of reading this output and turning it into an honest
final report, see `docs/EXP26_RESULTS.md` — it's the write-up of exactly
the run this guide walks you through setting up.

## 9. If something breaks

- **`ChromaDB Embedding function conflict` at server startup** — your
  `.env`'s `SCALED_EVALS_EMBED_BACKEND` doesn't match what the collection
  was seeded with. Re-seed with `--force` (step 4).
- **Every `/chat` call 500s, but the server itself starts fine** — same
  root cause, a subtler symptom (`InvalidArgumentError: Collection
  expecting embedding with dimension of X, got Y`). Same fix.
- **`401 Unrecognized API key`** — the bearer key you sent doesn't match
  any of `HARDENED_AGENT_{LEGAL,SUPPORT,OPS}_API_KEY` in `.env` exactly.
- **A live experiment script hangs or is unexpectedly slow** — Groq rate
  limits (`429 Too Many Requests`) are common and self-recovering
  (`aginiti/llm_client.py` retries and falls back to Gemini automatically)
  — check the console output for `HTTP/1.1 429` lines before assuming
  something's actually stuck.
- **Membership-inference scores look flat/uninformative** (both member and
  non-member score similarly) — almost certainly step 5's memory-
  contamination gotcha. Restart the server and re-run.
