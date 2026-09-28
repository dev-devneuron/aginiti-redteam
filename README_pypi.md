# Aginiti Red-Team Framework 🛡️🤖

[![PyPI Version](https://img.shields.io/pypi/v/aginiti-redteam.svg)](https://pypi.org/project/aginiti-redteam/)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Tests](https://img.shields.io/badge/tests-2010%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)]()

**Aginiti is an autonomous, evidence-driven red-teaming and penetration-testing engine for AI agents.**

Point Aginiti at any AI chatbot, RAG assistant, or tool-calling agent. Rather than running a static list of prompts, Aginiti plans adaptive multi-turn attack campaigns in real time: accumulating everything it observes into an active **Security State Graph (SSG)** and dynamically selecting the most effective attack techniques turn-by-turn.

---

## ⚡ Key Highlights

* **~5x Search Efficiency:** Reaches verified exploit states in 5x fewer queries than fixed-order scanners by steering around defense dead-ends.
* **Industry & Standards Aligned:** Evaluates target defenses against the **OWASP Top 10 for LLM Applications (2025)** and **MITRE ATLAS**.
* **Research-Backed Attack Suite:** Includes standalone RAG exfiltration (*IKEA*, *SECRET*), Shadow Membership Inference (*MIA*), System Prompt Extraction (*SPE-LLM*), Encoding & Low-Resource Language Evasions (*NeurIPS/ACL*), and Tool Abuse.
* **Instant Reports:** Generates structured `findings.json`, executive Markdown reports, and styled, interactive HTML reports automatically.

---

## 🚀 Installation

Install the core library and CLI:
```bash
pip install aginiti-redteam
```

To include the practice target agent (`aginiti-demo-target`) for local A/B testing:
```bash
pip install "aginiti-redteam[demo-target]"
```

---

## ⚙️ Configuration

Aginiti uses LLMs to plan campaigns, execute attacks, and judge target responses. 

**Open-Weight Model Key (Recommended):** Certain deep-attack techniques (such as RAG exfiltration analysis and shadow interrogation) require open-weight models (e.g. Llama 3.3). We strongly recommend setting a **Groq API key** (`GROQ_API_KEY`) alongside your preferred frontier provider (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).

**Any other LLM provider:** set `AGINITI_LLM_MODEL` to a [LiteLLM](https://docs.litellm.ai/docs/providers) `provider/model` string (e.g. `deepseek/deepseek-chat`, `openrouter/meta-llama/llama-3.1-70b-instruct`) and `AGINITI_LLM_API_KEY` to its key. When set, it is used for planning, attacks and judging, ahead of the keys above.

Create a `.env` file in your workspace:

**macOS / Linux**
```bash
echo 'OPENAI_API_KEY="sk-..."' > .env
echo 'GROQ_API_KEY="gsk_..."' >> .env
```

**Windows (PowerShell)**
```powershell
Set-Content -Path .env -Value 'OPENAI_API_KEY="sk-..."'
Add-Content -Path .env -Value 'GROQ_API_KEY="gsk_..."'
```

---

## 💻 CLI Quickstart

### 🚀 Option A: 1-Minute Automated Assessment Demo
Run the end-to-end automated demo (initializes environment, starts the hardened demo target in background, runs full assessment across all 47 operators, opens HTML report, and shuts down server):

**macOS / Linux**
```bash
curl -sSL https://raw.githubusercontent.com/dev-devneuron/aginiti-redteam/main/quickstart.sh | bash
```

**Windows (PowerShell)**
```powershell
irm https://raw.githubusercontent.com/dev-devneuron/aginiti-redteam/main/quickstart.ps1 | iex
```

---

### Option B: Step-by-Step Manual Commands

#### 1. Start a Practice Target (Optional)
Launch a local target agent seeded with multi-domain corporate records (HR, IT, DevSecOps, Vendor Invoices):

```bash
# Vanilla mode (defenses off — vulnerable baseline)
aginiti-demo-target --port 8001

# Hardened mode (all 5 defense layers enabled: input classifier, system guardrails, DLP redactor, rate limiter, memory)
aginiti-demo-target --port 8001 --hardened
```

### 2. Autonomous Multi-Turn Scan (`aginiti scan`)
Let Aginiti autonomously map vulnerabilities across the target:

```bash
# Full multi-domain assessment (tries all attack categories)
aginiti scan --target http://localhost:8001 --tier full_assessment --budget 50

# Or focus on specific security tiers:
aginiti scan --target http://localhost:8001 --tier data_leakage --budget 30
aginiti scan --target http://localhost:8001 --tier unauthorized_actions --budget 20
aginiti scan --target http://localhost:8001 --tier discovery_recon --budget 15
```

### 3. Targeted Deep Attacks (`aginiti attack`)
Run individual, research-grounded attack algorithms directly:

```bash
# IKEA: Mutational RAG exfiltration walk
aginiti attack ikea --target http://localhost:8001 --topic "corporate records" --queries 20

# SECRET: Adaptive jailbreak RAG extraction
aginiti attack secret --target http://localhost:8001 --domain "credentials and infrastructure" --queries 20

# SPE: Heuristic System Prompt Extraction sweep
aginiti attack spe --target http://localhost:8001

# MIA: Shadow Membership Inference against candidate records
aginiti attack mia --target http://localhost:8001 --dataset candidates.json
```

### 4. Regenerate Reports (`aginiti report`)
Rebuild Markdown and HTML reports from existing finding artifacts without re-running queries:

```bash
aginiti report --input results/2026-09-24_124156/findings.json
```

---

## 📊 Assessment Output & Reports

Every scan and attack run automatically creates a timestamped folder under `./results/` containing:
1. **`findings.json`**: Complete structured JSON output with OWASP mappings, confidence scores, and raw transcripts.
2. **`aginiti_assessment_report.md`**: Human-readable Markdown summary with severity breakdown and remediation advice.
3. **`aginiti_assessment_report.html`**: Beautiful, browser-ready interactive dashboard with visual status cards, automatically opened upon scan completion.

---

## 🐍 Python API

Aginiti can also be integrated directly into automated CI/CD security pipelines:

```python
from aginiti.attacks.dra.ikea import IKEAAttack

# Run a targeted black-box exfiltration audit
attack = IKEAAttack(
    target_url="http://localhost:8001",
    llm_provider="groq/llama-3.3-70b-versatile"
)

findings = attack.execute_black_box(topic="DevSecOps and AWS credentials", max_queries=20)

for finding in findings:
    if finding.confirmed:
        print(f"[{finding.severity.upper()}] Leaked: {finding.leaked_content}")
```

---

## 🔗 Links & Resources

* **GitHub Repository:** [https://github.com/dev-devneuron/aginiti-redteam](https://github.com/dev-devneuron/aginiti-redteam)
* **Documentation & Guides:** [Aginiti Docs](https://github.com/dev-devneuron/aginiti-redteam/tree/main/docs)
* **Authors:** [Muhammad Hammad Irfan](https://github.com/MuhammadHammadIrfan), [Omer Bin Dawood](https://github.com/OmerBinDawood)
* **License:** MIT
