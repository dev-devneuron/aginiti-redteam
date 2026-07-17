# Aginiti Redteam 🛡️🤖

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.12-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

**Aginiti Redteam** is an open-source security probing and red-teaming library built specifically to audit enterprise **agentic AI & RAG systems for data leakage**. It enables security engineers and developers to probe their RAG-based AI applications, classify exfiltration risks, and map security findings directly to the OWASP Top 10 for Large Language Model Applications.

Unlike generic LLM security tools, Aginiti Redteam is built from the ground up for RAG architectures—focusing on the interaction between user queries, vector search retrieval, and the final generation output.

---

## 🚀 Key Features

* **IKEA Data Reconstruction Attack (DRA):** Plugs in the arXiv:2505.15420 methodology. Generates natural-sounding, benign-looking queries using Embedding-space Resampling (ERS) and Topic-restricted Random Walk Mutation (TRDM) to bypass traditional keyword/jailbreak detectors.
* **Tiered Probing Architecture:**
  * **Tier 1 (Black-Box):** Probes the agent's HTTP endpoint. Evaluates exfiltration risk strictly from conversational responses.
  * **Tier 2 (White-Box/OTel):** Hooked into OpenTelemetry. Upgrades findings to "confirmed" by cross-referencing exfiltrated data with RAG retrieval spans.
* **LLM-as-a-Judge Classification:** Analyzes response text to classify disclosures into *PII*, *Verbatim*, *Sensitive Data*, *Schema*, or *None*, using customizable judge prompts.
* **Centralized Embeddings Layer:** Features local-first embeddings run on ChromaDB's bundled ONNX runtime (`all-MiniLM-L6-v2`)—enabling cost-free, high-performance offline exfiltration math.
* **CISO-Ready Markdown Reports:** Automatically generates detailed assessment reports outlining exfiltration metrics, risk tables, and remediation advice mapped to the OWASP LLM Top 10.

---

## 📁 Repository Structure

```text
aginiti-redteam/
├── aginiti/
│   ├── attacks/
│   │   ├── base.py              # Base class (BaseAttack) & findings schema (LeakFinding)
│   │   └── dra/
│   │       ├── ikea.py          # IKEA attack loop (ERS + TRDM)
│   │       └── README.md
│   ├── connectors/
│   │   ├── endpoint.py          # HTTP client for target agents
│   │   └── embedding.py         # Local ONNX & cloud embedding routing
│   └── reporting/
│       └── markdown_report.py   # Markdown report generator
├── benchmarks/
│   ├── dev_fixtures/            # Lightweight mock targets used in unit tests & local dev
│   │   ├── agents/              # Reference black-box and OTel-instrumented FastAPI agents
│   │   └── datasets/            # 25 synthetic Acme HR records
│   └── scaled_evals/            # Production-scale benchmarking suite
│       ├── agents/              # HealthCareMagic-1k FastAPI target agent
│       ├── datasets/            # prepare_healthcare.py download script
│       └── results/             # Saved evaluation runs
├── scripts/
│   ├── run_ikea.py              # Single-target IKEA run script
│   ├── run_benchmark.py         # Empirical scoring CLI
│   └── run_healthcare_benchmark.py # Preset HealthCareMagic benchmark runner
└── tests/                       # Complete offline test suite (all LLM & endpoints mocked)
```

---

## 🛠️ Installation & Developer Setup

### Prerequisites
* Python 3.10+
* A valid API key for any LiteLLM-supported provider (e.g., `GEMINI_API_KEY`, `OPENAI_API_KEY`, `GROQ_API_KEY`, etc.) as the attack loop and LLM-as-a-judge classification are fully provider-agnostic.

### Install
Clone the repository and install in editable mode with development dependencies:

```bash
git clone https://github.com/aginiti/aginiti-redteam.git
cd aginiti-redteam
pip install -e ".[dev]"
```

### 1. Seed & Start Reference Agents
Acme HR reference agents share a 25-record synthetic database but run on separate ports to isolate Tier 1 and Tier 2 setups:

```bash
# Seed the local ChromaDB vector databases (computes embeddings offline)
python -m benchmarks.dev_fixtures.agents.reference_agent_blackbox.seed
python -m benchmarks.dev_fixtures.agents.reference_agent_otel.seed

# Start reference agents in separate terminals
uvicorn benchmarks.dev_fixtures.agents.reference_agent_blackbox.main:app --port 8001
uvicorn benchmarks.dev_fixtures.agents.reference_agent_otel.main:app --port 8002
```

### 2. Run the IKEA Attack
Proactively attack the running Tier 1 black-box agent:

```bash
python scripts/run_ikea.py
```
This runs the ERS/TRDM loop and writes a JSON findings list along with an auto-generated Markdown report under `scripts/results/`.

---

## 📊 Benchmark Suite (HealthCareMagic-1k)

To evaluate exfiltration resistance against a realistic, production-scale corpus, Aginiti Redteam hosts an optional benchmarking suite utilizing the 1,000-record HealthCareMagic dataset.

### Setup and Start the Benchmark Target
```bash
# Install benchmark-specific packages
pip install -e ".[benchmarks]"

# 1. Download and sample the HuggingFace HealthCareMagic dataset
python benchmarks/scaled_evals/datasets/prepare_healthcare.py

# 2. Seed the medical vector database
python -m benchmarks.scaled_evals.agents.healthcare_agent.seed

# 3. Spin up the healthcare agent (port 8003)
uvicorn benchmarks.scaled_evals.agents.healthcare_agent.main:app --port 8003
```

### Run and Score
Execute the preset 50-query benchmarking loop to score exfiltration metrics against ground-truth consultations:

```bash
python scripts/run_healthcare_benchmark.py
```

The runner evaluates and logs:
* **ASR (Attack Success Rate):** The percentage of queries returning positive leak findings.
* **CRR (Content Reconstruction Rate):** ROUGE-L similarity between exfiltrated chunks and actual database records.
* **SS (Semantic Similarity):** Cosine similarity of embeddings to measure meaning preservation.
* **EE (Exfiltration Effectiveness):** Combined gating metric capturing genuine, non-trivial document leakages.

Run results are stored as timestamped `.json` and `.md` reports under `benchmarks/scaled_evals/results/`.

---

## 🧪 Testing

The library runs a robust unit test suite. All network requests, agent endpoints, and LLM completions are fully mocked—allowing the entire suite to run offline in seconds without incurring API costs:

```bash
pytest tests/ -v
```

---

## 🗺️ Roadmap & Status

* [x] **Data Reconstruction Attack (DRA)**
  * [x] IKEA Attack Method (ERS + TRDM)
  * [x] LLM-as-a-judge leak classification
  * [x] CISO-facing markdown reporter
  * [x] HealthCareMagic-1k benchmarking suite
* [ ] **Tier 2 OTel Trace Collector Integration** (Langfuse / OpenTelemetry ingress)
* [ ] **Membership Inference Attack (MIA)**
* [ ] **Feature/Attribute Inference Attack (FIA)**
* [ ] **SECRET DRA Technique** (Jailbreak-based exfiltration runner)
* [ ] **Command-Line Interface (`aginiti` CLI wrapper)**

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
