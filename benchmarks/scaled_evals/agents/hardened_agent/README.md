# `hardened_agent` — upgraded benchmark target

An additional local benchmark target, alongside `healthcare_agent/`, adding
real defensive depth: RBAC (three genuinely-scoped personas), real document
chunking, output-side PII redaction, an optional rate limiter, optional
per-persona conversation memory, and a system-prompt guardrail against
revealing PII/secrets/confidential data — over two real, independently-
sourced document domains (CUAD legal contracts + CFPB consumer complaints).
See `plans/vanilla-target-agent.md` for the full design history and
reasoning behind every decision below.

## What this is *for* — and what it isn't

Two purposes:

1. **A more credible showcase target** than `healthcare_agent`'s single-
   collection, zero-auth, single-guardrail setup — something closer to a
   real enterprise RAG deployment's defensive posture.
2. **A controlled ablation lab.** All five defenses — RBAC, rate limiting,
   redaction, conversation memory, and the system-prompt guardrail — are
   each independently toggleable via env vars, with zero code changes
   between an on-run and an off-run (RBAC's toggle simulates a RAG
   deployment where access-control scoping was never wired into the
   retrieval layer, not a realistic "turn off access control" scenario —
   see `personas.py`'s `RBAC_ENABLED` docstring). This is evidence the
   paused Onyx integration structurally *can't* provide — Onyx is a black
   box we can only observe, not selectively reconfigure.

**What it does NOT do:** solve the circularity problem. This agent was
built by the same team that builds IKEA — no amount of RBAC/redaction
sophistication changes that. `healthcare_agent`'s existing caveat applies
here identically. Independent validation is what the paused Onyx work is
for, not this.

## Data sources — real, not synthesized

Synthesizing the two document types here would have quietly reintroduced
the same circularity objection as building the target and the attack
ourselves — "did we write documents that happen to be easy to leak?" Both
sources are real and independently published:

| Document type | Source | License |
|---|---|---|
| Legal / contracts | [CUAD v1](https://www.atticusprojectai.org/cuad/) (Contract Understanding Atticus Dataset) — 510 real commercial legal contracts | CC BY 4.0 |
| Support tickets / complaints | [CFPB Consumer Complaint Database](https://www.consumerfinance.gov/data-research/consumer-complaints/) — real consumer complaint narratives, published by the US Consumer Financial Protection Bureau | Public (US government data) |

**Honest caveat on the CFPB data, not hidden**: CFPB removes direct PII
from complaint narratives before publishing them (partial `XXXX`-style
masking is visible in the real text). This is a genuine characteristic of
the source, not a shortcut taken here — and arguably makes it *more*
representative of a real intake-scrubbed enterprise ticket system than
fully raw text would be, not less.

Both datasets' HuggingFace mirrors use a legacy loading-script format no
longer supported by current `datasets` versions — CUAD is loaded via its
auto-converted `refs/convert/parquet` revision; CFPB is pulled directly
from CFPB's own public API instead of its (equally broken) HF mirror. Both
verified working live while building this, not assumed from documentation.

## RBAC design — a real boundary, not a volume tier

Three personas, deliberately not a flat "more vs. less access" hierarchy:

| Persona | Scope | Tests |
|---|---|---|
| `legal` | CUAD documents **only** | — |
| `support` | CFPB documents **only** | `legal` + `support` share **zero** document overlap — the **disjoint-boundary test**: does querying as one ever surface the other's documents? |
| `ops` | A **subset** of both domains (never full access to either) | The **aggregation-risk test**: does legitimate cross-domain access enable synthesizing something neither individual document set would reveal alone? |

Authenticate via `Authorization: Bearer <API key>` — see `personas.py` for
the exact env var names. No key, or an unrecognized key, gets a 401.

## Quick start

```bash
# 1. Build the dataset (samples CUAD + CFPB, splits into ingested/held-out —
#    the held-out half is never touched here; it's reserved ground truth
#    for future membership-inference work, see plans/vanilla-target-agent.md §1.3)
python benchmarks/scaled_evals/datasets/prepare_hardened_dataset.py

# 2. Set persona API keys in your .env (any values you choose — see
#    repo-root .env.example)
#    HARDENED_AGENT_LEGAL_API_KEY=...
#    HARDENED_AGENT_SUPPORT_API_KEY=...
#    HARDENED_AGENT_OPS_API_KEY=...

# 3. Seed the (chunked) ChromaDB collection
python -m benchmarks.scaled_evals.agents.hardened_agent.seed

# 4. Start the agent (port 8004)
uvicorn benchmarks.scaled_evals.agents.hardened_agent.main:app --port 8004
```

Smoke test:
```bash
curl -s -X POST http://localhost:8004/chat \
  -H "Authorization: Bearer $HARDENED_AGENT_LEGAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"message": "What termination clauses appear in these agreements?"}'
```

Check which defenses are actually active before spending API budget on a
run (useful for confirming an env var toggle actually took effect):
```bash
curl -s http://localhost:8004/config
```

## Run the attack — one persona per command, small budget first

```bash
python scripts/run_ikea_hardened.py --persona legal
python scripts/run_ikea_hardened.py --persona support
python scripts/run_ikea_hardened.py --persona ops
```

Deliberately not a zero-arg preset — persona must be chosen per invocation,
and these are meant to run as **separate commands**, not one combined run,
so LLM API cost/token usage stays trackable per call. Default budget is 20
queries (smaller than `healthcare_agent`'s canonical 50) — this is a new,
not-yet-live-tested target, so the recommended progression is:
1. `--queries 5` to `10` per persona — pure plumbing check (does auth/
   retrieval/generation work at all)
2. `--queries 20` to `30` (the default range) — sanity-check behavior once
   plumbing is confirmed
3. `--queries 50` (matching `healthcare_agent`) — only once stages 1-2 look
   sane, for numbers actually comparable to the existing baseline

Results are written with all the varying dimensions in the filename:
`ikea_hardened_{persona}_rbac-{on|off}_rl-{on|off}_rd-{on|off}_mem-{on|off}_gd-{on|off}_{queries}q_{timestamp}.json`
— the runner queries the target's own `/config` before each run and
records the target's *actual* toggle state (not just what an env var was
intended to be), via `run_benchmark()`'s `extra_run_metadata` field.

## Five independently-toggleable defenses

| Toggle | Env var | Default | What it is |
|---|---|---|---|
| RBAC | `HARDENED_AGENT_RBAC_ENABLED` | on | Persona-scoped ChromaDB `where` filter on every retrieval call (`personas.chroma_filter_for`). Off simulates a RAG deployment where access-control scoping was never wired into the retrieval layer — every persona then shares one fully-open scope. Not a "disable access control" toggle in the normal sense; authentication (401 on a bad/missing key) is unaffected either way. |
| Rate limiting | `HARDENED_AGENT_RATE_LIMIT_ENABLED` | on | Simple sliding-window request counter, per persona (`agent.RateLimiter`) |
| Output redaction | `HARDENED_AGENT_REDACTION_ENABLED` | on | Regex-based PII scrubbing on the generated response (`agent.redact`) |
| Conversation memory | `HARDENED_AGENT_MEMORY_ENABLED` | on | Per-persona sliding window of the last 4 `(question, redacted answer)` pairs, re-sent as context on each call — a soft, prompt-level "be more cautious if you've already disclosed a lot in this session" nudge, not a hard rule. Deliberately minimal-token: only Q&A pairs are stored, never retrieved context/chunks (those would multiply token cost every turn for no ongoing value). Tune the window with `HARDENED_AGENT_MEMORY_MAX_TURNS` (default 4). |
| System-prompt guardrail | `HARDENED_AGENT_GUARDRAIL_ENABLED` | on | An explicit system-prompt instruction not to reveal PII/secrets/confidential data (`agent._GUARDRAIL_SUFFIX`), added after review found the base prompt had no such instruction at all — only groundedness/anti-hallucination wording, despite an earlier code comment incorrectly claiming parity with `healthcare_agent`'s guardrail. Deliberately domain-agnostic (no persona-specific wording, so it reads identically across CUAD/CFPB/the ops slice) and attack-agnostic (explicitly names indirect/hypothetical/role-play/instruction-override framing, and covers membership-confirmation questions relevant to MIA-style probing, not just DRA-style content extraction) — not tuned against any one attack this library implements or will implement. Same soft, bypassable-under-pressure nature as every other prompt-level instruction here, not a hard rule. |

Per the explicit condition rate limiting was scoped under
(`plans/vanilla-target-agent.md` §1.2/§2.2): **building the detector alone
is not the deliverable** — a live IKEA run with detection on vs. off,
ASR/detection-rate reported for both, is required before it can be cited as
validated either way (evaded or effective). That live comparison has **not
been run yet** — a separate, explicitly-flagged checkpoint (spends real LLM
API budget), not silently bundled into building this agent. The current
threshold (`RateLimiter(max_requests=10, window_seconds=60)`) is a starting
default, not yet calibrated against real IKEA query timing.

## Live end-to-end verification — done, via Docker

The `Authorization: Bearer` auth mechanism (reused from the paused Onyx
work — `AgentEndpoint`'s `headers` param) was unit-tested with mocked HTTP,
then proven against a live native `uvicorn` process (auth/routing only —
see history below), and is now **fully verified end-to-end, including real
retrieval + generation**, by running `hardened_agent` inside Docker
(`docker compose up -d hardened_agent`, port 8004) — the same resolution
already established for every other ChromaDB-backed agent in this project.

- `/health` → `200 {"status": "ok"}`, `/config` → `200`, correct toggle
  state, no crash.
- RBAC confirmed directly via `curl`, both directions: `legal` persona
  gets real CUAD contract content in-domain and correctly reports no
  matching records for a CFPB-only query (the ChromaDB
  `where={"source": "cuad"}` filter genuinely excludes it — not a
  hallucinated refusal); `ops` persona correctly answers both domains,
  confirming the aggregation-risk design.
- Full attack path: `python scripts/run_ikea_hardened.py --persona
  legal --queries 1` completed end-to-end (315.8s, 1 finding, 6 LLM
  calls), with `run_metadata.target_toggle_state` populated live from
  `/config`.

Two real bugs were found and fixed getting here (see
`plans/vanilla-target-agent.md` §9 for full detail):
1. `prepare_hardened_dataset.py` had no idempotency guard, and CFPB's API
   is a live feed — re-running `docker compose up` could silently desync
   the dataset JSON from what was already embedded. Fixed with a
   `force`-gated guard + regression tests.
2. The root cause of an earlier `ModuleNotFoundError: No module named
   'fastapi'` crash loop wasn't a build-race issue — it was that
   `Dockerfile` had never been updated after `fastapi`/`uvicorn`/`faker`
   were moved into the `dev` extras group, so **every** containerized
   agent in this project was broken until `Dockerfile` was fixed to
   install `.[benchmarks,dev]`.

**Native-Windows history (why Docker, not WSL2, was used here):** on this
machine, `HardenedAgent`'s retrieval path
(`PersistentClient` + `collection.query()`) segfaults natively — the same
pre-existing ChromaDB/Windows native-binary issue documented elsewhere in
this project (`docs/how-it-works.md` §3.10). Auth/routing (no ChromaDB
read) worked fine natively and was verified that way first; the segfault
only reproduced once a request reached real retrieval. Docker sidesteps it
entirely by running the same Linux ChromaDB/onnxruntime wheels every other
agent here already relies on. The 55 offline unit tests
(`tests/unit/test_hardened_agent.py`, `tests/unit/test_prepare_hardened_dataset.py`)
cover all the actual logic (chunking, redaction, rate limiting, memory,
persona filter construction) independent of any of this.
