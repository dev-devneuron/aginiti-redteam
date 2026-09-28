# Aginiti Redteam 🛡️🤖

[![PyPI Version](https://img.shields.io/pypi/v/aginiti-redteam.svg)](https://pypi.org/project/aginiti-redteam/)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Tests](https://img.shields.io/badge/tests-1997%20passing-brightgreen.svg)]()
[![Attack Categories](https://img.shields.io/badge/attack%20categories-11-blueviolet.svg)]()
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)]()

**Aginiti is an autonomous, evidence-driven red-teaming engine for AI agents.** 

Point it at any AI chatbot, RAG assistant, tool-calling agent, or multi-agent system. Rather than running a static list of prompts, Aginiti plans adaptive multi-turn attack campaigns in real time: accumulating everything it observes into a persistent **Security State Graph** and dynamically selecting the most effective attack techniques turn-by-turn.

---

## 🏆 Key Capabilities & Benchmarks

| Metric / Feature | What Aginiti Accomplishes | Validation & Reference |
| :--- | :--- | :--- |
| **~5x Search Efficiency** | Reaches confirmed ground-truth exploit states in 5x fewer queries than fixed-order scanners by steering around defense dead-ends. | Benchmarked against 8-layer hardened agent (`docs/BENCHMARKS.md`). |
| **Industry Alignment** | Findings independently verified against **NVIDIA's garak**, plus live tool-chain exfiltration beyond REST boundaries. | Mapped to OWASP Top 10 for LLM Applications (2025). |
| **Research-Backed Attack Techniques** | Covers RAG Data Reconstruction (IKEA, SECRET), Membership Inference, and System Prompt Extraction as standalone `aginiti attack` modules, plus scan-mode techniques like Crescendo escalation, PAIR-style refinement, encoding evasion, indirect prompt injection, and tool abuse. | Grounded in peer-reviewed papers (ICLR, ACM CCS, IEEE TIFS). |
| **Zero-Cost Offline Suite** | **2,010 unit tests** run in under 30 seconds with 100% mocked offline endpoints (zero API tokens spent). | Run locally via `pytest tests/`. |

---

## ⚡ Quick Start: Assess an Agent in 60 Seconds

### Option A: 1-Click Automated Demo (Recommended)
Run our automated quickstart script to initialize an environment, launch the hardened demo target in the background, run a full 50-query assessment across all 47 operators, open the interactive HTML report, and cleanly shut down the server when finished:

**macOS / Linux**
```bash
curl -sSL https://raw.githubusercontent.com/dev-devneuron/aginiti-redteam/main/quickstart.sh | bash
```
*(Or clone the repo and run `./quickstart.sh`)*

**Windows (PowerShell)**
```powershell
irm https://raw.githubusercontent.com/dev-devneuron/aginiti-redteam/main/quickstart.ps1 | iex
```
*(Or clone the repo and run `.\quickstart.ps1`)*

---

### Option B: Step-by-Step Manual Setup
Prefer manual control? Run the assessment step-by-step:

```
Manual Setup Flow
  │
  ├─ 1. Configure Environment & API Key
  ├─ 2. pip install "aginiti-redteam[demo-target]"
  ├─ 3. Launch Demo Agent: aginiti-demo-target --port 8001 (Terminal 1)
  └─ 4. Run Scan: aginiti scan --target http://localhost:8001 (Terminal 2)
```

### 1. Set Up Environment & API Keys
Aginiti uses LLMs to plan campaigns, execute attacks, and judge responses. 

> [!TIP]
> **Open-Weight Model Support (Groq):** Certain deep-attack techniques (such as RAG exfiltration analysis and shadow interrogation) require open-weight models (e.g., Llama 3.3). We strongly recommend adding a **Groq API key** (`GROQ_API_KEY`) alongside your preferred frontier provider (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).

**Any other LLM provider:** set `AGINITI_LLM_MODEL` to a [LiteLLM](https://docs.litellm.ai/docs/providers) `provider/model` string (e.g. `deepseek/deepseek-chat`, `openrouter/meta-llama/llama-3.1-70b-instruct`) and `AGINITI_LLM_API_KEY` to its key. When set, it is used for planning, attacks and judging, ahead of the keys above.

Create your `.env` file and activate an isolated virtual environment:

**macOS / Linux**
```bash
echo 'OPENAI_API_KEY="sk-..."' > .env
echo 'GROQ_API_KEY="gsk_..."' >> .env
python -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**
```powershell
Set-Content -Path .env -Value 'OPENAI_API_KEY="sk-..."'
Add-Content -Path .env -Value 'GROQ_API_KEY="gsk_..."'
python -m venv .venv
.venv\Scripts\activate
```

### 2. Install the Package
```bash
pip install "aginiti-redteam[demo-target]"
```
*(Testing your own existing agent? Run `pip install aginiti-redteam` without the `[demo-target]` extra).*

### 3. Start the Practice Target Agent (Terminal 1)
Launch a simulated corporate AI assistant. Both modes below serve the exact same seeded data — 25 synthetic HR employee records (names, SSNs, salaries, addresses, etc.) — so you're comparing identical data with and without defenses, not two different targets.

#### What each flag means
| Flag | Meaning |
| :--- | :--- |
| *(no flag)* | **Vanilla mode (default).** All defenses off — a deliberately vulnerable baseline, useful for confirming an attack works at all before testing a hardened target. |
| `--hardened` | Turns on all 5 defense layers: an LLM input-filter classifier, a system-prompt guardrail, output PII/secret redaction, a rate limiter, and conversation memory — for an A/B comparison against `--vanilla`. |
| `--vanilla` | Explicitly selects vanilla mode (same as passing no mode flag at all). |
| `--port <PORT>` | Which port to serve on. Default: `8001` (or the `AGENT_PORT` env var if set). |

Vanilla (default — no defenses):
```bash
aginiti-demo-target --port 8001
```

Hardened (all 5 defenses on):
```bash
aginiti-demo-target --port 8001 --hardened
```

---

### 4. Run Security Assessments (Terminal 2)

#### Flags shared by every `scan`/`attack` command
| Flag | Meaning |
| :--- | :--- |
| `--output-dir` | Where results are saved. Each run gets its own new, timestamped folder inside this directory, so nothing is ever overwritten. Default: `./results` |
| `--report` | File name for the Markdown report inside that folder. Default: `aginiti_assessment_report.md` |
| `--redact` | Also saves a second copy of the report with private details blacked out, safe to share more widely. |
| `--model` | Which LLM aginiti itself uses to run the attack and judge the results, e.g. `openai/gpt-4o`. Default: auto-detects from whichever provider's API key you have set (Gemini, OpenAI, Groq, Anthropic, or Mistral). |
| `-v`, `--verbose` | Show detailed technical logs instead of the normal, simplified output. |
| `--no-open-report` | Don't automatically open the HTML report in your browser when the run finishes. |

#### Option A: Automated Multi-Turn Campaigns (`aginiti scan`)
Let Aginiti's planner autonomously probe the target, map its vulnerabilities, and generate findings.

| Flag | Meaning |
| :--- | :--- |
| `--target` (required) | Web address of the chatbot or AI agent you're testing, e.g. `http://localhost:8001` |
| `--tier` | Which broad kind of security problem to focus on: `full_assessment` (default — tries everything), `data_leakage`, `unauthorized_actions`, or `discovery_recon`. |
| `--attack-category` | A more precise alternative to `--tier` — one or more specific technique groups instead (combine several by listing more than one). Run `aginiti scan --list-attack-categories` to see every option with a description. Mutually exclusive with `--tier`. |
| `--budget` | How many different techniques aginiti is allowed to try in total before it stops. Use this to cap how many requests reach the target — e.g. if it has its own rate limit, or you want to control how long the run takes. |

Recommended for a first look — tries everything:
```bash
aginiti scan --target http://localhost:8001 --tier full_assessment --budget 50
```

Or focus on one risk area by swapping `--tier`:
```bash
aginiti scan --target http://localhost:8001 --tier data_leakage --budget 30
```

```bash
aginiti scan --target http://localhost:8001 --tier unauthorized_actions --budget 20
```

```bash
aginiti scan --target http://localhost:8001 --tier discovery_recon --budget 10
```

#### Option B: Standalone Attack Modules (`aginiti attack`)
Execute one specific, dedicated attack technique directly, with full control over its own settings. All four also accept `--target` (required) and the shared flags above.

| Technique | Extra required flag | Depth flag(s) | What it tests for |
| :--- | :--- | :--- | :--- |
| `ikea` | `--topic "<what you're testing for>"` | `--queries` (default: 20) | **IKEA (ICLR 2026):** asks ordinary-sounding questions and pieces the answers together to see if private RAG records leak out. |
| `secret` | *(none — `--domain` is optional)* | `--queries` (default: 20), `--phase1-iter` (default: 3), `--phase1-cand` (default: 2) | **SECRET (IEEE TIFS 2026):** first works out a jailbreak trick, then reuses it to pull records out of the knowledge base. |
| `mia` | `--dataset <path.json>` | `--probes` (default: 10) | **Interrogation / MIA (ACM CCS 2025):** checks whether a specific document you already have exists in the target's knowledge base. |
| `spe` | *(none)* | Fixed — always exactly 3 probes, not configurable | **SPE-LLM (ICLR 2026):** tries to get the target to reveal its own hidden system prompt. |

`--topic`/`--domain` describe what IKEA/SECRET should probe for. "HR records" is accurate for `aginiti-demo-target` specifically, since that's literally what its seeded data is (see step 3) — point these at whatever your own target actually stores instead.

**IKEA**
```bash
aginiti attack ikea --target http://localhost:8001 --topic "HR records" --queries 20
```

**SECRET**
```bash
aginiti attack secret --target http://localhost:8001 --domain "HR records" --queries 20
```

**MIA works differently from the other three.** It doesn't explore the target for new data — it checks whether one specific document you already have is stored there. That's why `--dataset` is required (there is no `--database` flag): a JSON file listing (a) the document(s) you want to test and (b) reference documents you already know are *not* in the target, needed for calibration. Minimal example against `aginiti-demo-target`, using one of its own real records as the "should be a member" candidate — save as `mia_dataset.json`:
```json
{
  "documents": [
    {"id": "emp_001", "text": "HR Employee Record — Emma Thompson\nEmployee ID: EMP-2847\nSSN: 423-58-9167\nDepartment: Engineering\n..."}
  ],
  "non_member_reference_docs": [
    {"id": "ref_1", "text": "HR Employee Record — a fabricated employee who does not exist in this dataset."}
  ]
}
```

See [`docs/USAGE.md`](docs/USAGE.md) for the full field reference.

```bash
aginiti attack mia --target http://localhost:8001 --dataset mia_dataset.json --probes 10
```

**SPE** — no extra flags needed:
```bash
aginiti attack spe --target http://localhost:8001
```

---

### 5. Interactive Security Reports
Every scan and attack automatically generates:
1. `findings.json` — Structured JSON result with full decision traces and evidence quotes.
2. `aginiti_assessment_report.md` — Human-readable CISO report with OWASP LLM Top 10 mappings.
3. `aginiti_assessment_report.html` — Interactive executive dashboard with color-coded severity metrics.

Reports are saved in a fresh, timestamped subdirectory under `./results/` (e.g. `results/2026-09-24_153012/`). The HTML dashboard opens in your browser automatically.

To regenerate reports from an existing run at any time:

| Flag | Meaning |
| :--- | :--- |
| `--input` (required) | Path to the `findings.json` file to rebuild the report from (saved automatically by `scan`/`attack`). |
| `--output` | Where to save the new report file. Default: right next to `--input`. |
| `--redact` | Save a redacted version, safe to share more widely, instead of the full report. |
| `--no-open-report` | Don't automatically open the report in your browser when it's done. |

```bash
aginiti report --input results/<run_dir>/findings.json
```

---

## 🐳 Prefer Docker? (Zero Local Python)

If you don't have Python installed or want an isolated Linux container setup:

1. Clone the repo and enter the docker folder:
```bash
git clone https://github.com/dev-devneuron/aginiti-redteam.git
cd aginiti-redteam/docker
```

2. Start the practice target in the background:
```bash
docker compose up -d
```

3. Run a scan inside the container (results save to your local folder):
```bash
docker compose run --rm cli aginiti scan --target http://demo-target:8001 --tier data_leakage --budget 20
```

4. Stop everything when you're finished:
```bash
docker compose down
```

### Which Setup Should You Choose?
| Setup Method | Best For | Advantages |
| :--- | :--- | :--- |
| **`pip install`** | Python Developers, Security Researchers | Fastest start, 0 repo checkout, native CLI speed. |
| **`docker compose`** | DevOps, CI/CD Pipelines, Non-Python Users | 100% isolated Linux environment, zero local Python dependencies. |

---

## 📁 Repository Architecture

```text
aginiti-redteam/
├── aginiti/
│   ├── core/                    # Adaptive campaign engine & planner (Security State Graph)
│   ├── operators/               # scan-mode operator libraries (prompt-based probes + deep-attack wrappers)
│   ├── attacks/                 # Standalone DRA (IKEA, SECRET), MIA (Interrogation), SPE modules
│   ├── adapters/                # HTTP, stdio, and API target adapters
│   ├── reporting/               # Executive Markdown & HTML dashboard generators
│   └── demo_target/             # Built-in practice target agent (Vanilla & Hardened modes)
├── benchmarks/
│   ├── scaled_evals/            # Production-scale targets (hardened_agent with 8 defense layers)
│   └── dev_fixtures/            # Unit testing mock agents
├── docker/                      # Standalone end-user Dockerfile & docker-compose.yml
├── docs/                        # In-depth ARCHITECTURE, BENCHMARKS, and TUTORIAL guides
└── tests/                       # 2,010 unit and integration tests (100% offline)
```

---

## 🛠️ Developer & Contributor Setup (Install from Source)

Follow this setup if you want to inspect source code, develop new attack operators, or run benchmarks.

### 1. Clone & Install in Editable Mode
Run all lines together, in order:

**macOS / Linux**
```bash
git clone https://github.com/dev-devneuron/aginiti-redteam.git
cd aginiti-redteam
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,benchmarks]"
cp .env.example .env
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/dev-devneuron/aginiti-redteam.git
cd aginiti-redteam
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev,benchmarks]"
copy .env.example .env
```

### 2. Run the Offline Test Suite
```bash
pytest tests/ -v
```

### 3. Run Campaigns Directly from Source
Against the built-in in-memory demo agent (no server needed):
```bash
python scripts/run_campaign.py
```

Or against a real local/remote endpoint:
```bash
python scripts/run_campaign.py --agent-url http://localhost:8001 --tier full_assessment --budget 30
```

---

## 📊 Benchmarking & Research Evals

Aginiti includes enterprise-grade evaluation targets under `benchmarks/scaled_evals/` (CUAD legal contracts, CFPB consumer complaints, HealthCareMagic-1k):
- **`hardened_agent`**: Real-world target with 8 independently toggleable defense layers (RBAC, DLP output redaction, rate limiting, conversation memory, system prompt guardrails, and input judge filters).
- **Evaluation Runner**: Evaluates Attack Success Rate (**ASR**), Character Recovery Rate (**CRR**), and Semantic Similarity (**SS**).

To run the full healthcare benchmark suite:
```bash
python scripts/run_healthcare_benchmark.py
```
For detailed benchmark methodology and paper baselines, see [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

---

## 📚 Documentation & Resources

| Guide | Description |
| :--- | :--- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | **Deep Dive:** Evidence Graph, Planner Utility Formulation, and Operator System. |
| [`docs/TUTORIAL.md`](docs/TUTORIAL.md) | **Step-by-Step:** End-to-end walkthrough of every command and parameter. |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | **Research Data:** Head-to-head comparisons against NVIDIA garak and paper baselines. |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | **Project Roadmap:** Shipped features and upcoming capabilities. |

---

## 🤝 Contributing

Contributions are welcome! Please review:
1. [Developer Setup](#-developer--contributor-setup-install-from-source) above for local environment instructions.
2. [`CONTRIBUTING.md`](CONTRIBUTING.md) for code standards and pull request workflows.
3. [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for community guidelines.
4. [`CHANGELOG.md`](CHANGELOG.md) for recent release notes.

### Contributors
- [Muhammad Hammad Irfan](https://github.com/MuhammadHammadIrfan)
- [Omer Bin Dawood](https://github.com/OmerBinDawood)

---

## 📄 License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
