# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Commands

```bash
# Install (from repo root) — editable mode with test deps
pip install -e ".[dev]"

# Seed vector stores — run once per machine before starting agents
python -m benchmarks.agents.reference_agent_blackbox.seed
python -m benchmarks.agents.reference_agent_otel.seed

# Start reference agents (two terminals)
uvicorn benchmarks.agents.reference_agent_blackbox.main:app --port 8001
uvicorn benchmarks.agents.reference_agent_otel.main:app --port 8002

# Run tests (no API key required — all LLM/HTTP calls are mocked)
pytest tests/ -v

# Run a single test file
pytest tests/test_base.py -v

# Regenerate synthetic ground-truth data (Faker seed=42)
python benchmarks/dev_fixtures/datasets/seed_data.py
```

### Full public-dataset benchmark (optional — real Gemini API cost, ~$3–8/run)

Separate from the fixture flow above. Measures attack *effectiveness* against a
live agent over the HealthCareMagic-1k dataset (the IKEA paper's dataset). Full
detail in `docs/benchmarking.md`.

```bash
# Install the optional benchmark deps (datasets + rouge-score)
pip install -e ".[benchmarks]"

# 1. Download + sample 1,000 rows (one-time, seed=42)
python benchmarks/scaled_evals/datasets/prepare_healthcare.py

# 2. Seed the healthcare agent's ChromaDB collection (--force to rebuild)
python -m benchmarks.scaled_evals.agents.healthcare_agent.seed

# 3. Start the target agent (port 8003)
uvicorn benchmarks.scaled_evals.agents.healthcare_agent.main:app --port 8003

# 4. Run the attack + score EE/ASR/CRR/SS (zero-arg preset, timestamped output)
python scripts/run_healthcare_benchmark.py
# ...or the flexible CLI for a different attack/agent/hyperparameters:
python scripts/run_benchmark.py --help
```

**Required env var:** `GEMINI_API_KEY` — only key needed for all dev/test workflows.
Read via `python-dotenv`'s `load_dotenv()` in `seed.py`/`main.py`, so a
repo-root `.env` file works (no need to `export` in the shell).
Optional: `AGENT_MODEL` overrides the LLM used by reference agents (default:
`gemini/gemini-3.5-flash`); `EMBED_MODEL` overrides the embedding model
(default: `chromadb/all-MiniLM-L6-v2` — **local ONNX, no API key, zero embedding
cost**; the model downloads ~90MB once on first seed/run and is cached at
`~/.cache/chroma/onnx_models/`). Seeding builds a ChromaDB collection, not a
JSON file.

**Native-binary note (Windows) — use WSL2, not version pins (verified
2026-07-12):** some Windows machines reject onnxruntime's/ChromaDB's compiled
native binaries outright — `import onnxruntime` DLL errors, or ChromaDB's Rust
core segfaulting on `add()`/`query()`. This turned out to be a Windows-native-
binary compatibility problem, not a real dependency defect: the exact same
versions (chromadb 1.5.9, onnxruntime 1.23.2, numpy 2.2.6 — current latest,
zero pins) install and run cleanly under WSL2 on the same physical machine.
**Recommended fix: develop inside WSL2.** This is standard practice for Python
projects with compiled native deps, not a workaround specific to this repo, and
it means contributors track current dependency versions instead of a frozen
pre-1.0 ChromaDB / old onnxruntime build.
One WSL-specific gotcha: **create the venv on the Linux filesystem** (e.g.
`~/venvs/aginiti-redteam`), not under `/mnt/c/` or `/mnt/d/` — `python -m venv`
on a Windows-mounted (DrvFs) path silently omits `pip`/`activate` scripts.
Point that venv's `pip install -e .` at the repo wherever it lives (`/mnt/d/...`
is fine for the *code*, just not for the *venv* itself).
The old per-machine pins (`onnxruntime==1.17.0`+`numpy==1.26.4`,
`chromadb>=0.5,<0.6`) remain documented as a fallback in `docs/how-it-works.md`
§3.10 for anyone who can't use WSL2, but are no longer the primary guidance.
(The mocked test suite needs none of this — it never imports chromadb.)

---

# aginiti-redteam — Project Context for Claude Code

This file is read automatically at the start of every Claude Code session in
this repo. It is the single source of truth for project identity, decisions
made so far, and working rules. Keep it updated as decisions change — stale
context here is worse than no context.

---

## 1. What this project is

**aginiti-redteam** is an **open source Python library** for red-teaming
enterprise agentic AI systems against **data leakage**. It is built by
Aginiti, a security platform for enterprise agentic AI systems, operating
under DevNeuron. The project owner/maintainer is Haider (founder); the
primary builder is devneuron (intern).

**This is not a demo, prototype, or personal project.** It is intended for
**public release and real-world enterprise adoption**. Every decision —
code structure, naming, error handling, documentation, test coverage — should
be made as if external contributors and enterprise security teams will read,
audit, and depend on this code. Treat code quality, API ergonomics, and
documentation as first-class deliverables, not afterthoughts bolted on at
the end.

**Why this matters concretely:** a security tool with sloppy docs or an
unstable API will not get enterprise adoption no matter how good the attack
methodology is. Trust is the product as much as the code is.

---

## 2. What we are building (v0 scope)

A Python library that lets security teams, founders, and engineers probe
their own enterprise RAG-based agentic AI systems for data leakage, working
against three attack categories:

- **DRA** — Data Reconstruction Attack: extract verbatim or near-verbatim
  content from a RAG knowledge base.
- **MIA** — Membership Inference Attack: determine whether a specific
  document/fact exists in the RAG store.
- **FIA** — Feature/Attribute Inference Attack: infer sensitive attributes
  without verbatim extraction. Lowest priority, build last.

### Tier architecture (locked, do not casually modify)

- **Tier 1 — black-box / endpoint only.** Must work standalone with zero
  instrumentation, against any HTTP-accessible agent. This is the core value
  of the tool and must never be treated as optional or secondary.
- **Tier 2 — endpoint + OTel traces.** An *enhancement* layer that upgrades
  evidentiary confidence (e.g. "suspected" → "confirmed" findings) by
  cross-referencing Tier 1 results against retrieval spans. It does not
  replace or duplicate Tier 1 attack logic — `execute_with_traces` should
  reuse `execute_black_box`'s extraction and add confirmation on top.
- **Tier 3 — + logprobs.** Out of scope for now, design-only.

**Design rule that must never be silently violated:** OTel/traces are never
a requirement for an attack to produce real findings. If an implementation
detail would make Tier 1 non-functional without traces, stop and flag it —
do not implement it that way.

### v0 vs v1

v0 = the attack library (this repo, current focus). v1 = a future
LangGraph-based autonomous agent that orchestrates v0 as a tool library.
**v1 is explicitly out of scope.** Do not introduce LangGraph orchestration,
autonomous multi-step agent behavior, or automatic report-generation
pipelines into v0 under any circumstances, even if it seems like a small
addition. If something v1-shaped seems useful, name it and ask, don't build it.

---

## 3. Locked architectural decisions

These are decided. Do not redesign them without an explicit instruction to
do so — if you think one is wrong, say so and explain why, but don't change
it unilaterally.

- **`LeakFinding` dataclass and `BaseAttack` abstract class** in
  `aginiti/attacks/base.py` are locked. Field names, types, and the
  `execute()` dispatch logic (black_box vs traces based on `self.otel`) must
  not change without explicit sign-off.
  **Sign-off history:** 2026-07-13, `LeakFinding` gained three additive
  optional fields (`full_response`, `leak_type`, `reasoning`) for LLM-as-judge
  leak classification; same date, `BaseAttack._init_llm`'s `_call` closure
  gained a provider-agnostic rate-limit retry (catches `litellm.RateLimitError`
  — normalized across all providers by litellm — parses a "try again in Xs"
  hint if present, else waits a flat 60s, up to 5 retries) since litellm's own
  `num_retries` backoff retries too fast to survive a real per-minute RPM/TPM
  window. Neither changed `execute()`'s dispatch logic or any existing field.
  Same-day follow-up (after a live Groq TPM-limit run): wait now escalates
  (doubles) if the same call keeps failing after waiting the hinted amount,
  capped at 60s — a single hinted wait is trusted once, but not repeated
  blindly. `num_retries` default dropped from 3 to 0 — litellm's own internal
  retry was *also* retrying rate-limit errors near-instantly, wasting
  requests against an already-exhausted budget and flooding the console with
  its own noise; `litellm.suppress_debug_info = True` set to silence that
  console noise (litellm's own `Router` sets this same flag for the same
  reason). Trade-off flagged: a one-off non-rate-limit transient error (bad
  connection, DNS blip) no longer gets an automatic litellm-level retry.
  Second same-day follow-up (after a live Groq **TPD**, not TPM, exhaustion —
  real waits of 2-7+ minutes, which the 60s cap was truncating, causing all 5
  retries to fail and then an uncaught crash with 0 findings saved):
  `_rate_limit_wait_seconds` now parses compound durations ("7m12s") fully
  and returns the real, uncapped duration. Waits below a new 90s
  `_RATE_LIMIT_FAILOVER_THRESHOLD_SECONDS` still sleep+retry as before; waits
  at/above it are no longer slept through at all — `BaseAttack.__init__`/
  `_init_llm` gained optional additive `fallback_llm_provider`/
  `fallback_api_key` params, and a long wait immediately tries that backup
  provider for the call instead of blocking. No fallback configured (or the
  fallback also failing) means the exception is raised immediately (no
  wasted sleep) — `IKEAAttack.execute_black_box` (`aginiti/attacks/dra/ikea.py`)
  now catches `openai.APIError` (the true common base of every
  litellm-normalized provider exception — verified via MRO that
  `litellm.RateLimitError` is *not* a subclass of `litellm.APIError` despite
  the name, they're siblings under `openai.APIError`) around the
  per-chain `_generate_query` call and degrades gracefully: stops the attack
  loop and returns whatever findings were already collected, instead of
  crashing. `scripts/run_benchmark.py`'s `run_benchmark()` also wraps
  `attack_instance.execute(...)` as a second safety net, so results are
  always written to disk (with the error recorded in `run_metadata`) even if
  something still escapes both layers.
- **LLM provider abstraction is mandatory everywhere.** Every LLM call inside
  the library goes through LiteLLM via `BaseAttack._init_llm`. Never hardcode
  a provider, an SDK, or assume a specific response shape. Default dev/test
  provider is `gemini/gemini-3.5-flash` (devneuron has no GPT/Claude API
  keys currently) — every example, test, and default config must work with
  just a `GEMINI_API_KEY` env var (or a Groq/other key via `AGENT_MODEL`).
- **Embedding architecture (locked, 2026-07-09 — REVERSES the earlier
  no-ChromaDB rule).** The default embed model is `chromadb/all-MiniLM-L6-v2`
  (local ONNX, no API key). **ChromaDB is a hard dependency** — it provides
  both the vector store AND the ONNX embedding function. **PyTorch is never a
  dependency** (onnxruntime only, shipped transitively by chromadb; do not add
  onnxruntime/sentence-transformers/torch explicitly). **Gemini/cloud APIs are
  used ONLY for LLM completion** (anchor/query/mutation generation), never for
  default embeddings. The JSON vector store (`vector_store.json` + numpy cosine)
  is **removed — do not reintroduce it.** Do NOT move the default `embed_model`
  back to a cloud API without explicit sign-off: embedding cost is severe
  (thousands of calls per attack run — this reversal exists because
  Gemini-REST embeddings ran ~$9/day).
  **History:** an earlier iteration *removed* ChromaDB (onnxruntime native-dep
  friction + a `litellm.embedding()`→Gemini 404) in favor of a JSON store +
  direct Gemini-REST `embed_texts()`. That was reversed by the 2026-07-09
  overhaul: the 404 is moot (default path is local ONNX, no Gemini embedding
  call) and the native-dep cost is accepted to kill the API bill. On Windows,
  onnxruntime needs the MS Visual C++ Redistributable x64 — if `import
  onnxruntime` fails with a DLL error, **the recommended fix is to develop
  inside WSL2** (verified 2026-07-12: latest chromadb/onnxruntime/numpy, no
  pins, work cleanly there), not to chase VC++ installs or pin dependency
  versions. See the Native-binary note above and `docs/how-it-works.md` §3.10.
- **Reference agents are deliberately minimal**, not feature-complete
  enterprise simulations: one ChromaDB collection + one LLM call path, no
  tools, no multi-step reasoning. Three targets exist:
  `benchmarks/dev_fixtures/agents/reference_agent_blackbox` (Tier 1, port 8001, no
  guardrail), `reference_agent_otel` (Tier 2, port 8002, no guardrail), and
  `benchmarks/scaled_evals/agents/healthcare_agent` (full-benchmark target, port 8003,
  a deliberate soft system-prompt guardrail — the "benchmarking configs later"
  complexity anticipated here). Do not gold-plate the fixture agents.
- **`AgentEndpoint`** (in `aginiti/connectors/endpoint.py`) is a generic HTTP
  client with configurable request/response keys — it must not assume the
  target's schema matches our own reference agents exactly.
- **`embed_texts`** (in `aginiti/connectors/embedding.py`) is the single
  embedding entry point for the whole library — attacks and reference agents
  alike. It routes `chromadb/*` → local ONNX and every other `<provider>/*` →
  `litellm.embedding()`. Do not call ChromaDB's embedding function or
  `litellm.embedding()` directly elsewhere; go through this function so routing
  stays centralized.

---

## 4. DRA paper selection — decided, with reasoning (read this before touching dra.py)

We evaluated multiple candidate papers for the DRA module. Final decision:

### Primary implementation target: **IKEA / "Silent Leaks"** (arXiv 2505.15420)
- Mechanism: benign-query, no-jailbreak knowledge extraction via two
  components — **Experience Reflection Sampling** (anchor concept sampling
  weighted against past unrelated/refused queries) and **Trust Region
  Directed Mutation** (iterative anchor mutation under cosine similarity
  constraints to maximize unexplored coverage).
- Fully black-box (Tier 1) by construction — the attacker's mechanism never
  touches the target's retriever, embedding model, or LLM internals, only
  query/response text via the attacker's *own* embedding model. That
  attacker-side embedding model defaults to `chromadb/all-MiniLM-L6-v2` (local
  ONNX, zero API cost) — see the **locked embedding architecture** in §3. The
  paper used `all-mpnet-base-v2`, so benchmark numbers differ from its Table 1;
  this is documented, not hidden.
- No official code release exists. Implement from the paper's algorithm
  description (Sec 3.2–3.4, hyperparameters in Appendix A.1/Table 5). Do not
  go looking for a GitHub repo — there isn't one.
- Why this one first, over SECRET: durability (exploits architectural/vector-
  space properties that can't be patched by a vendor safety update, unlike
  jailbreak-dependent methods) and detection evasion (bypasses input/output
  defenses by design, since queries are benign). Full reasoning is in
  project history — ask devneuron if context is needed.

### Documented as planned v0.x follow-up: **SECRET** (arXiv 2510.02964)
- Mechanism: three-component framework — extraction instruction + jailbreak
  operator (LLM-as-optimizer generates jailbreak wrappers) + cluster-focused
  retrieval triggering.
- Also black-box (Tier 1) by threat model, but jailbreak-dependent — more
  fragile against vendor patches and more detectable by input-level
  defenses than IKEA.
- This is the next DRA technique to add (e.g. `aginiti/attacks/dra/secret.py`
  or similar), **not yet started**. Do not begin implementing this until
  IKEA is built, tested, and explicitly approved.

### Both papers — Tier 1/Tier 2 implementation note
Neither paper requires OTel to function. When implementing each attack's
`execute_with_traces`, do not reimplement the extraction logic — call
`execute_black_box` internally, then post-process each `LeakFinding` by
checking `self.otel` for matching retrieval spans and upgrading
`confirmed`/`severity` when a match is found. This keeps Tier 1 the single
source of attack logic and Tier 2 a pure confidence-upgrade layer.

---

## 5. Build status (update this section as work lands)

| Component | Status |
|---|---|
| `aginiti/attacks/base.py` (LeakFinding, BaseAttack) | Done, reviewed |
| `aginiti/connectors/endpoint.py` (AgentEndpoint) | Done |
| `aginiti/connectors/embedding.py` (embed_texts — ChromaDB local ONNX default + litellm cloud path) | Done — rewritten 2026-07-09 |
| `benchmarks/dev_fixtures/agents/reference_agent_blackbox` | Done |
| `benchmarks/dev_fixtures/agents/reference_agent_otel` | Done |
| `benchmarks/dev_fixtures/datasets/ground_truth.json` (25 HR records) | Done |
| Tests for the above | Done |
| `aginiti/attacks/dra/` — IKEA implementation | Done — 69 tests, all passing |
| Full benchmark: `benchmarks/scaled_evals/datasets/prepare_healthcare.py` (HealthCareMagic-1k) | Done |
| Full benchmark: `benchmarks/scaled_evals/agents/healthcare_agent` (port 8003, soft-guardrail baseline) | Done |
| Full benchmark: `scripts/run_benchmark.py` (CLI runner + EE/ASR/CRR/SS) + `scripts/run_healthcare_benchmark.py` (preset) | Done — infra only, not yet run |
| `docs/benchmarking.md` | Done |
| `aginiti/instrument/` — OTel span ingester | Stub only |
| `aginiti/reporting/` — Markdown assessment report generator | Done (2026-07-13) — `generate_markdown_report()`, wired into `scripts/run_ikea.py` and `scripts/run_benchmark.py` (so `run_healthcare_benchmark.py` gets it too); 19 tests |
| MIA module | Not started |
| FIA module | Not started |
| SECRET (second DRA technique) | Documented, not started |
| `RandomDRAAttack` baseline / multi-domain 500+ dataset / guardrail env-var dimension | Not started (roadmap) |
| `aginiti/cli.py` | Not started |

---

## 6. Industry-adoption standards (apply throughout, not just "later")

Because this is a public OSS security tool, hold every contribution to these
bars from the start, not retroactively:

- **Docstrings on every public class/function** — what it does, parameters,
  return type, and for attack modules, which paper/section it implements.
- **A `README.md` per major module** (at minimum: `aginiti/attacks/dra/`,
  the repo root) explaining what it is, how to use it, and any safety/ethics
  notes (this is a security tool — usage should be scoped to authorized
  testing of systems the user controls or has permission to test).
- **Type hints everywhere.** This is a library other engineers will import
  and rely on; untyped public APIs are a real adoption blocker.
- **Tests for every attack module** — at minimum, unit tests against the
  reference agents with known ground truth, so extraction claims are
  verifiable, not just plausible-looking.
- **No silent failures.** If a probe fails, a defense blocks a query, or an
  LLM call errors, that should surface as structured information (this is
  partly why `LeakFinding.confirmed`/`confidence` exist) — never swallowed.
- **Root `README.md`** should make the project's purpose, install steps, and
  a minimal usage example legible to someone landing on the GitHub page cold
  — assume the reader is a CISO or security engineer evaluating whether to
  trust this tool, not just a Python developer.

---

## 7. Working rules for Claude Code in this repo

- **Do not start implementing the next roadmap item on your own initiative.**
  Wait for an explicit instruction from devneuron in the terminal before
  beginning `dra.py`, the OTel ingester, the reporting module, MIA, FIA, or
  anything else. Finishing a task and then immediately starting the next
  listed item without being asked is not acceptable, even if the next step
  seems obvious from this file.
- When asked to implement something, **state your plan before writing code**
  for anything nontrivial (e.g. "here's how I'll structure Experience
  Reflection Sampling and TRDM as functions, mapped to the paper's Eq. 2–7")
  and wait for confirmation before proceeding, unless explicitly told to
  just go ahead.
- **Flag deviations explicitly.** If you make a judgment call that extends
  or departs from what's specified here or in an explicit instruction, say
  so in plain language — don't silently improvise on locked decisions
  (Section 3) and don't bury a deviation in code comments only.
- If something in this file seems wrong, outdated, or in conflict with a
  new instruction, say so — don't just follow it blindly, and don't just
  follow the new instruction blindly either. Surface the conflict.
- Keep Section 5 (build status) and Section 4 (paper decisions) updated as
  work progresses and decisions evolve — this file should remain accurate,
  not just exist.