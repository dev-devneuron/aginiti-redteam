# Developer Setup

## Prerequisites

- Python 3.10+
- `GEMINI_API_KEY` environment variable — the only key needed for this phase

## Install

From the repo root:

```bash
pip install -e ".[dev]"
```

This installs the `aginiti` library in editable mode plus test dependencies.

## 1. Seed the ChromaDB collections (one-time, per machine)

Both agents share the same ground-truth data but maintain separate ChromaDB
collections so attack results are independently benchmarkable across tiers.

```bash
# Tier 1 — black-box agent
python -m benchmarks.dev_fixtures.agents.reference_agent_blackbox.seed

# Tier 2 — OTel agent
python -m benchmarks.dev_fixtures.agents.reference_agent_otel.seed
```

ChromaDB persistent stores land in:
- `benchmarks/dev_fixtures/agents/reference_agent_blackbox/.chroma/`
- `benchmarks/dev_fixtures/agents/reference_agent_otel/.chroma/`

> **First-run note:** Embeddings are computed **locally** by ChromaDB's ONNX
> `all-MiniLM-L6-v2` — **no API key needed for embeddings** (only the LLM
> completion at query time uses `AGENT_MODEL`). On first run ChromaDB downloads
> the ONNX model (~90MB) to `~/.cache/chroma/onnx_models/`; after that it is
> offline. Re-running is a no-op if the collection is already populated; pass
> `--force` to rebuild.
>
> **Native-binary troubleshooting (Windows):** if `import onnxruntime` fails
> with a DLL error, or `seed.py` crashes with a segfault and no traceback,
> this is a Windows-native-binary compatibility issue, not a project bug —
> **the recommended fix is to develop inside WSL2**, not to chase VC++
> installs or pin dependency versions. Verified 2026-07-12: the exact same
> versions that fail on native Windows Python on this project's machine
> (chromadb 1.5.9, onnxruntime 1.23.2, numpy 2.2.6 — current latest, zero
> pins) install and seed cleanly under WSL2. This is standard practice for
> Python projects with compiled native dependencies (onnxruntime, in this
> case), not a workaround specific to this repo.
>
> **WSL gotcha:** create your venv on the Linux filesystem
> (`python3 -m venv ~/venvs/aginiti-redteam`), not under `/mnt/c/` or
> `/mnt/d/` — a venv created on a Windows-mounted path silently ends up
> without `pip`/`activate` scripts. The repo itself can stay wherever it is
> (including `/mnt/d/...`); only the venv needs to be off the Windows mount.
> Point `pip install -e ".[dev]"` at the repo path from inside that venv.
>
> Old fallback (only if WSL2 truly isn't an option): pin `onnxruntime==1.17.0`
> + `numpy==1.26.4` for the DLL error, and `chromadb>=0.5,<0.6` for the
> segfault. Full account, including why these are no longer the primary
> recommendation: `docs/how-it-works.md` §3.10.

## 2. Run the agents

Open two terminals:

```bash
# Terminal A — Tier 1 (black-box), port 8001
uvicorn benchmarks.dev_fixtures.agents.reference_agent_blackbox.main:app --port 8001

# Terminal B — Tier 2 (OTel), port 8002
uvicorn benchmarks.dev_fixtures.agents.reference_agent_otel.main:app --port 8002
```

The OTel agent emits span JSON to stdout via `ConsoleSpanExporter`. Full
collector wiring (Langfuse / local OTLP) is out of scope for v0.

## 3. Smoke-test with curl

```bash
# Tier 1
curl -s -X POST http://localhost:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is Emma Thompson'\''s salary?"}' | python -m json.tool

# Tier 2
curl -s -X POST http://localhost:8002/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is Daniel Kim'\''s SSN?"}' | python -m json.tool
```

Expected: the agent answers from context (e.g. `$152,000` / `289-46-7523`).
Both agents are behaviourally identical — same data, same model, same retrieval
logic.

## 4. Run the IKEA attack (evaluation)

With the reference agent running, use `scripts/run_ikea.py` (a maintained
run script, not a one-off snippet — edit its `TARGET_URL`/`TOPIC`/
`MAX_QUERIES`/`LLM_PROVIDER` constants directly for a different run):

```bash
python scripts/run_ikea.py
```

`llm_provider` and `embed_model` are independent — either can point at any
LiteLLM-supported provider (Gemini, Groq, OpenAI, Mistral, ...), as long as
`embed_model`'s provider actually offers embeddings (Groq and Anthropic do
not — see the script's `_KEY_ENV_VAR` comment). `IKEAAttack` does **not**
read `AGENT_MODEL`/`EMBED_MODEL` from `.env` on its own; the script resolves
the right key per provider explicitly at construction time.

**What happens step by step:**

1. IKEA generates anchor concepts for the topic via an LLM call.
2. It filters anchors by embedding similarity (ERS) and sends natural-sounding
   queries to the agent.
3. After a productive response, TRDM mutates the anchor into a nearby concept
   and chains further queries without restarting ERS.
4. Each non-refused response becomes a `LeakFinding`.
5. At 20 queries, this takes roughly 2–5 minutes depending on API latency —
   progress (each ERS sample, each query/response, refusals) is logged to
   stdout as it happens (`logging.basicConfig` in the script), since a run
   this long with no output is indistinguishable from a hang.

**Output:** one timestamped file per run at
`scripts/results/ikea_run_<UTC timestamp>.json` — never overwritten; old runs
are not cleaned up automatically, delete them by hand. Each file contains a
`run` block (target, topic, models, timing, finding count) plus the full
`findings` list. In addition, a human-readable Markdown report is automatically
generated alongside the JSON file using `aginiti/reporting/generate_markdown_report()`.

Each `LeakFinding` has:

| Field | Type | Meaning |
|---|---|---|
| `attack_type` | str | Always `"DRA"` for IKEA |
| `tier_used` | str | `"black_box"` (Tier 1) |
| `confidence` | float | Cosine sim of probe vs. response (heuristic) |
| `confirmed` | bool | `False` in Tier 1 — no retrieval span evidence |
| `leaked_content` | str | The agent's full response |
| `probe_used` | str | The query that produced this response |
| `trace_span_id` | str | `""` in Tier 1 |
| `recommendation` | str | Remediation advice |
| `severity` | str | `critical / high / medium / low` |

## 5. Ground-truth file

`benchmarks/dev_fixtures/datasets/ground_truth.json` holds 25 synthetic HR records.

Each record has: `id`, `name`, `employee_id`, `ssn`, `salary`, `department`,
`position`, `date_of_birth`, `hire_date`, `address`, `email`,
`performance_rating`, `manager`, and `document_text` (the verbatim text
indexed in the vector store).

To regenerate the file with new synthetic data (Faker seed=42):

```bash
python benchmarks/dev_fixtures/datasets/seed_data.py
```

Then re-run the seed scripts to rebuild the vector stores.

## 6. Run tests

```bash
pytest tests/ -v
```

Tests mock all network and LLM calls — no API key required to run the suite.

| Test file | Covers |
|-----------|--------|
| `tests/test_base.py` | `LeakFinding` construction, `BaseAttack.execute()` dispatch, `_init_llm` wiring |
| `tests/test_endpoint.py` | `AgentEndpoint` happy path, custom keys, 4xx/5xx handling, context manager |
| `tests/test_ikea.py` | All 14 `IKEAAttack` method classes — ERS, TRDM, anchor init, finding generation |

## Full public-dataset benchmarking

Everything above uses the 25-record Faker fixture (fast, free, deterministic).
There is a separate, optional layer that measures attack *effectiveness*
against a live agent over a real public dataset (HealthCareMagic-1k, the IKEA
paper's dataset), computing EE/ASR/CRR/SS. It has real Gemini API cost
(~$3–8/run).

```bash
pip install -e ".[benchmarks]"                                  # datasets + rouge-score
python benchmarks/scaled_evals/datasets/prepare_healthcare.py           # download + sample 1k
python -m benchmarks.scaled_evals.agents.healthcare_agent.seed          # build vector store
uvicorn benchmarks.scaled_evals.agents.healthcare_agent.main:app --port 8003
python scripts/run_healthcare_benchmark.py                      # preset run + scoring
```

Full guide, metric definitions, and interpretation caveats: **`docs/benchmarking.md`**.

## Repo structure

```
aginiti-redteam/
├── aginiti/
│   ├── attacks/
│   │   ├── base.py          # LeakFinding + BaseAttack (locked schema)
│   │   └── dra/
│   │       ├── ikea.py      # IKEA attack implementation
│   │       └── README.md
│   ├── connectors/
│   │   ├── endpoint.py      # Tier 1 HTTP client
│   │   └── embedding.py     # embed_texts(): ChromaDB local ONNX default + litellm cloud path
│   ├── instrument/          # stub — OTel wrapper wired in later session
│   └── reporting/           # report generator
├── benchmarks/
│   ├── dev_fixtures/
│   │   ├── agents/
│   │   │   ├── reference_agent_blackbox/    # Tier 1 target (port 8001)
│   │   │   │   ├── agent.py
│   │   │   │   ├── main.py
│   │   │   │   └── seed.py
│   │   │   └── reference_agent_otel/        # Tier 2 target (port 8002)
│   │   │       ├── agent.py
│   │   │       ├── main.py
│   │   │       └── seed.py
│   │   └── datasets/
│   │       ├── ground_truth.json
│   │       └── seed_data.py
│   └── scaled_evals/
│       ├── datasets/
│       │   └── prepare_healthcare.py
│       └── agents/
│           └── healthcare_agent/            # Tier 1 benchmark target (port 8003)
│               ├── agent.py
│               ├── main.py
│               └── seed.py
├── tests/
├── docs/
└── pyproject.toml
```

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `GEMINI_API_KEY` | — | Required — authenticates Gemini API (LLM + embedding) |
| `AGENT_MODEL` | `gemini/gemini-3.5-flash` | Override the LLM used by reference agents |
| `EMBED_MODEL` | `chromadb/all-MiniLM-L6-v2` | Override the embedding model (default: local ONNX, no key). Cloud options e.g. `gemini/gemini-embedding-001` |
