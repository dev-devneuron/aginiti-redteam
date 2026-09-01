# Aginiti Redteam 🛡️🤖

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Tests](https://img.shields.io/badge/tests-1827%20passing-brightgreen.svg)]()
[![Attack Categories](https://img.shields.io/badge/attack%20categories-11-blueviolet.svg)]()
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)]()

**Aginiti is an autonomous red-teaming engine for AI agents.** Point it at a chatbot, a
RAG-backed assistant, a tool-calling agent, or a multi-agent fleet, and it plans a real
attack campaign against it — accumulating everything it learns into a persistent evidence
graph and deciding what to try next from that graph, turn by turn. No fixed prompt list, no
scripted chain: it reasons about the target the way a human red-teamer would, at machine
speed and scale.

Two things live in this repo, and you can use either independently:

1. **The adaptive campaign engine** (`aginiti/core/`) — a planner that ranks every currently
   eligible attack by a multi-term utility function (information gain, chain progress,
   diagnosed failure patterns, …), executes the top pick, records what happened as
   Fact → Observation → Claim evidence, and repeats. This is the actual novel part of the
   project — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.
2. **A standalone attack library** (`aginiti/attacks/`) — IKEA and SECRET (two independent
   Data Reconstruction Attacks), and an Interrogation/Membership-Inference attack — each
   runnable directly against one target via its own script, or wrapped as planner-selectable
   `Operator`s so the engine above can decide *when* they're worth their budget.

Every real target is probed through the same evidence pipeline: raw responses are judged
(deterministically where possible, by an LLM otherwise) **and** cross-checked against an
independent, non-LLM disclosure oracle before anything counts as a confirmed finding.

---

## 🏆 Results

Aginiti isn't validated on toy examples. It's benchmarked head-to-head against honest
baselines and an industry-standard scanner, on real, independently-built targets:

- **~5x fewer requests than fixed-order enumeration** to reach the same ground-truth
  outcomes against a production-realistic target with 8 independently-toggleable defense
  layers (RBAC, output redaction, rate limiting, a dedicated input-filter classifier, and
  more) — and **cut requests the target's own filter blocked by over 98%**, evidence the
  planner is steering around dead ends mid-campaign, not succeeding through brute volume.
- **Validated against [NVIDIA's garak](https://github.com/NVIDIA/garak):** on every
  directly comparable attack category, Aginiti's findings agreed exactly with garak's —
  plus real, confirmed findings (live tool exfiltration, network egress) that a
  REST-only scanner is structurally unable to see at all.
- **11 named attack methodologies**, from direct prompt injection to RAG poisoning to
  multi-step MCP tool-chain composition, grounded in **9+ published, cited research
  papers** — ArtPrompt, Crescendo, PAIR, CipherChat/MetaCipher, the Interrogation Attack,
  IKEA, SECRET, InjecAgent, and STAC among them.
- **1,827 tests, fully offline** — every LLM and network call mocked, full suite in
  under 30 seconds, zero API cost.

Full methodology, numbers, and citations: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

---

## 🚀 Quickstart (2 minutes, zero targets to set up)

The fastest way to see Aginiti actually plan and execute a live campaign — no servers, no
seeding, one API key:

```bash
# 1. Clone and enter the project
git clone https://github.com/dev-devneuron/aginiti-redteam.git
cd aginiti-redteam

# 2. Create a virtual environment and install
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# 3. Add one LLM API key (Aginiti's own reasoning — the judge, the planner's
#    ranking calls — needs a provider; the in-memory demo target needs no key at all)
cp .env.example .env
#   edit .env and set GEMINI_API_KEY=... or GROQ_API_KEY=...

# 4. Run a full campaign against the built-in mock target
python scripts/run_campaign.py
```

That last command runs a real adaptive campaign — ranks operators, executes the winner,
judges the response, updates the evidence graph, and repeats — against an in-memory demo
agent (a payroll/GitHub/helpdesk assistant with a deliberately exploitable trust
relationship). You'll see a full decision trace and a final `Security State Graph`. On an
unmodified checkout this reliably ends with `payroll_write_unauthorized = confirmed` and
`Ground truth -- any mission path actually achieved: True` — a real indirect-prompt-injection
chain, planned and executed end to end, from a cold start, with no target-specific code
written for it.

**Point it at a real target instead of the mock one:**

```bash
python scripts/run_campaign.py --agent-url http://localhost:8001 \
    --tier data_leakage --budget 15
```

`--tier` filters to one of 4 COARSE buckets — `data_leakage | unauthorized_actions |
discovery_recon | full_assessment`. For a PRECISE selection instead, use `--attack-category`
to pick from the 11 named attack-methodology groups directly (`direct_prompt_attack`,
`encoding_attack`, `rag_poisoning`, `indirect_injection`, `tool_discovery`,
`tool_manipulation`, `markdown_network_exfiltration`, `multi_step_chain`, plus 3
planner-evaluation controls) — run `python scripts/run_campaign.py --list-attack-categories`
to see every option with a one-line description before choosing:

```bash
# Only encoding-evasion attacks:
python scripts/run_campaign.py --agent-url http://localhost:8001 \
    --attack-category encoding_attack --budget 20

# Two categories at once (a union):
python scripts/run_campaign.py --agent-url http://localhost:8001 \
    --attack-category encoding_attack rag_poisoning --budget 25
```

`--tier` and `--attack-category` are mutually exclusive (pick one granularity). `--budget` caps
how many prompts the campaign may spend; `--model` overrides the attacker LLM used by the
deep-attack operators (IKEA/SECRET/MIA). The same category filter is available directly in
Python via `OperatorLibrary.by_category("encoding_attack", ...)`
([`aginiti/operators/library.py`](aginiti/operators/library.py)) for any other caller, not
just this script. See `scripts/run_campaign.py`'s own module docstring for the full flag
reference.

**Want to run one specific attack technique on its own** (IKEA, SECRET, or the Interrogation
attack), rather than letting the planner decide? See [§ Standalone attack library](#-standalone-attack-library-ikea--secret--interrogation-mia) below.

**Windows users:** native `onnxruntime` (used by the default local embedding backend) can hit
DLL-loading issues on native Windows. Running inside **WSL2** or Docker
(`docker build -t aginiti-redteam . && docker compose up` — see the [`Dockerfile`](Dockerfile)
and [`docker-compose.yml`](docker-compose.yml) at the repo root) is the smoothest path; the
Quickstart above also works natively on Windows in most environments, it's only the optional
local-embedding path that's more reliable under WSL2/Docker.

---

## 📁 Repository Structure

```text
aginiti-redteam/
├── aginiti/
│   ├── core/                    # The campaign engine — the project's actual core
│   │   ├── graph/                    # Security State Graph: Fact/Observation/Claim schema,
│   │   │                             #   taxonomy tags (attack_category, security_boundary, …)
│   │   ├── planner/                  # AginitiPlanner — the multi-term utility-ranking function
│   │   ├── policies/                 # Policy interface + Static/Random baselines for A/B comparison
│   │   ├── mission.py                 # Success criteria, budget, risk threshold
│   │   ├── campaign.py                 # run_campaign() — the plan→act→observe→repeat loop
│   │   ├── observation_adapter.py     # Every response's single interpretation point
│   │   │                             #   (deterministic extractor -> LLM judge -> independent oracle)
│   │   └── llm.py                     # Provider-agnostic LLM client (Groq/Gemini, auto-fallback)
│   ├── operators/                # Operator libraries — one module per target/technique family;
│   │                             #   see docs/ARCHITECTURE.md for the full catalog
│   ├── adapters/                 # One BaseAdapter subclass per real/mock target — the only
│   │                             #   place target-specific transport (HTTP, stdio, a gateway) lives
│   ├── attacks/
│   │   ├── base.py                    # BaseAttack & the LeakFinding schema
│   │   ├── dra/                       # Data Reconstruction Attacks: IKEA, SECRET
│   │   └── mia/                       # Interrogation Attack (Membership Inference)
│   ├── connectors/                # HTTP client for target agents; local/cloud embedding routing
│   └── reporting/                 # Markdown/PDF report generation
├── benchmarks/
│   ├── dev_fixtures/             # Lightweight mock targets used in unit tests & local dev
│   └── scaled_evals/             # Production-scale targets: hardened_agent (RBAC + 8 independently
│                                 #   -toggleable defenses), healthcare_agent, dataset prep scripts
├── experiments/                  # Every live A/B experiment script (Aginiti vs. Random vs. Static
│                                 #   policy) + its results under experiments/results/
├── scripts/
│   ├── run_campaign.py           # The general-purpose entry point — see Quickstart above
│   ├── run_ikea.py / run_secret.py / run_interrogation.py   # Standalone single-attack runners
│   └── run_healthcare_benchmark.py  # Preset benchmark against the HealthCareMagic-1k corpus
├── docs/                         # ARCHITECTURE.md, BENCHMARKS.md, ROADMAP.md
└── tests/                        # 1,827 tests, fully offline (every LLM/HTTP call mocked)
```

---

## 🛠️ Installation & Developer Setup

### Prerequisites
* Python 3.10+
* A valid API key for any LiteLLM-supported provider (`GEMINI_API_KEY`, `GROQ_API_KEY`,
  `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, …) — the planner's reasoning, the judge, and the
  attack loops are all provider-agnostic via [LiteLLM](https://github.com/BerriAI/litellm).
* **Windows users:** see the Quickstart note above — WSL2 or Docker is the most reliable
  path for anything that touches the local ONNX embedding backend.

### Install & Configure

```bash
git clone https://github.com/dev-devneuron/aginiti-redteam.git
cd aginiti-redteam
python3 -m venv .venv
source .venv/bin/activate

# Core install (campaign engine + attack library + dev/test tooling, incl. FastAPI/Uvicorn
# for the local reference-target servers below):
pip install -e ".[dev]"

# Optional: the public-dataset benchmarking layer (benchmarks/scaled_evals/)
pip install -e ".[benchmarks]"

cp .env.example .env   # then fill in at least one LLM API key
```

`.env.example` documents every variable this project reads — model overrides, the local vs.
cloud embedding backend, and the `hardened_agent` persona keys/defense toggles — with the
reasoning for each default inline.

### Run the local reference agents (Tier 1 / Tier 2 black-box + OTel targets)

```bash
# Seed the local ChromaDB vector databases (computes embeddings offline, no API cost)
python -m benchmarks.dev_fixtures.agents.reference_agent_blackbox.seed
python -m benchmarks.dev_fixtures.agents.reference_agent_otel.seed

# Start them (separate terminals)
uvicorn benchmarks.dev_fixtures.agents.reference_agent_blackbox.main:app --port 8001
uvicorn benchmarks.dev_fixtures.agents.reference_agent_otel.main:app --port 8002
```

Then point the campaign engine or a standalone attack at `http://localhost:8001` (see
Quickstart above, or the standalone-attack section below).

---

## 🎯 Standalone attack library (IKEA · SECRET · Interrogation/MIA)

Each of these is independently runnable against one target with its own script — the right
tool when you want to measure one specific technique's effectiveness in isolation, with
output directly comparable to that technique's own paper. (The same three attacks are also
available as planner-selectable `Operator`s — see `aginiti/operators/deep_attack_operators.py`
— when you'd rather let the campaign engine decide whether they're worth the budget relative
to everything else it could try.)

* **IKEA — Data Reconstruction Attack (DRA):** ICLR 2026 (arXiv:2505.15420). Generates
  natural-sounding, benign-looking queries via Embedding-space Resampling (ERS) and
  Topic-restricted Random Walk Mutation (TRDM) to bypass keyword/jailbreak detectors.
* **SECRET — jailbreak-optimized DRA:** IEEE TIFS 2026 (arXiv:2510.02964). An
  Optimizer/Evaluator LLM loop calibrates a jailbreak prompt against the live target, then
  Cluster-Focused Triggering alternates exploration and exploitation to extract knowledge-base
  clusters. Every query is jailbreak-wrapped — see
  [`aginiti/attacks/dra/README.md`](aginiti/attacks/dra/README.md) before assuming it behaves
  like IKEA.
* **Interrogation Attack — Membership Inference (MIA):** ACM CCS 2025 (arXiv:2502.00306).
  Confirms or denies whether a specific document you already hold exists in the target's
  knowledge base via calibrated yes/no probing. See
  [`aginiti/attacks/mia/README.md`](aginiti/attacks/mia/README.md) — a genuinely different
  threat model from DRA.

```bash
# Against the Tier 1 black-box reference agent started above:
python scripts/run_ikea.py
```

This writes a JSON findings list plus an auto-generated Markdown report under
`scripts/results/`.

**Tiered probing architecture:**
* **Tier 1 (Black-Box):** probes the agent's HTTP endpoint; evaluates exfiltration risk
  strictly from conversational responses.
* **Tier 2 (White-Box/OTel):** hooked into OpenTelemetry; upgrades findings to "confirmed" by
  cross-referencing exfiltrated data with RAG retrieval spans.

---

## 📊 Benchmarking against real, defended targets

`benchmarks/scaled_evals/` hosts production-scale targets over real corpora (CUAD legal
contracts, CFPB consumer complaints, HealthCareMagic-1k medical consultations):

* **`healthcare_agent`** (port 8003) — a stateless RAG target, no RBAC split. Measures each
  attack's effectiveness *ceiling* against an undefended/softly-guardrailed target.
* **`hardened_agent`** (port 8004) — the harder, more realistic question: how much do real,
  layered defenses (RBAC-scoped retrieval, output redaction, rate limiting, conversation
  memory, a system-prompt guardrail, a dedicated input-filter classifier, session/auth expiry,
  and RBAC-scoped tool-calling — **8 independently-toggleable layers**) actually reduce
  extraction, and what still gets through anyway?

```bash
pip install -e ".[benchmarks]"
python benchmarks/scaled_evals/datasets/prepare_healthcare.py
python -m benchmarks.scaled_evals.agents.healthcare_agent.seed
uvicorn benchmarks.scaled_evals.agents.healthcare_agent.main:app --port 8003
python scripts/run_healthcare_benchmark.py
```

The runner scores **ASR** (Attack Success Rate), **CRR** (Content Reconstruction Rate — ROUGE-L
against real records), **SS** (Semantic Similarity), and **EE** (Exfiltration Effectiveness, a
combined gating metric). Results land as timestamped JSON/Markdown under
`benchmarks/scaled_evals/results/`.

For real results interpreting exactly this kind of run — including a full head-to-head
against Random/Static baselines and against NVIDIA's garak — see
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

---

## 🧪 Testing

The full test suite mocks every network call, agent endpoint, and LLM completion — it runs
offline, in seconds, at zero API cost:

```bash
pytest tests/ -v
```

1,827 tests currently pass on a clean checkout.

---

## 📚 Where to go next

| Doc | What it covers |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | **Start here.** How Aginiti works — the evidence graph, the planner, the full attack catalog |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Real results — the garak head-to-head, live planner-advantage experiments, and every research citation |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | What's shipped, what's in progress, what's next, and how to contribute |

---

## 🗺️ Status

Evidence-driven adaptive planning, multi-step discovery, composite severity scoring, data
reconstruction attacks, membership inference, and a production-realism hardened target are
all shipped and live-tested. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full picture
— what's shipped, what's actively being scaled up, and what's next.

---

## 👥 Contributors

- [Omer Bin Dawood](https://github.com/OmerBinDawood)
- [Muhammad Hammad Irfan](https://github.com/MuhammadHammadIrfan)

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
