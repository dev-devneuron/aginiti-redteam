# Aginiti Red-Team Framework 🛡️🤖

**Aginiti** is an autonomous security-assessment and penetration-testing engine for
enterprise agentic AI systems — chatbots, RAG assistants, tool-calling agents, and
multi-agent fleets.

Rather than executing a static list of prompts and checking pass/fail, Aginiti builds an
active **Security State Graph (SSG)** of the target, evaluates security controls, and
plans multi-step exploits autonomously — the way a human red-teamer reasons, at machine
speed.

**Proven, not just architected:** benchmarked head-to-head against fixed-order
enumeration (~5x fewer requests to the same outcomes) and validated against NVIDIA's
garak (findings agreed exactly on every comparable category) on real, production-realistic
targets. 11 attack methodologies, grounded in 9+ published research papers, 1,827 tests.
Full numbers: [`docs/BENCHMARKS.md`](https://github.com/dev-devneuron/aginiti-redteam/blob/main/docs/BENCHMARKS.md).

---

## 🚀 Installation

Install the core library (for running standalone attacks and HTTP adapters):
```bash
pip install aginiti-redteam
```

If you plan to run the autonomous campaign orchestrator with advanced integrations (like LangChain agents, OpenTelemetry tracing, or Model Control Protocol stdio servers), install the adaptive extras:
```bash
pip install aginiti-redteam[adaptive]
```

---

## ⚙️ Configuration & Prerequisites

Aginiti campaigns use an LLM provider to evaluate vulnerability conditions, judge target responses, and calculate attacker utility.

Set up your API keys in your environment or a `.env` file:
```env
# Attacker/Judge LLM keys (LiteLLM routes these automatically)
GROQ_API_KEY=your_groq_api_key
GEMINI_API_KEY=your_gemini_api_key
OPENAI_API_KEY=your_openai_api_key
```

---

## 💻 Usage Guide

Aginiti supports two modes of execution: **Direct Mode** (for full-scale standalone audits) and **Adaptive Mode** (for autonomous orchestrated campaigns).

### **1. Direct Mode (Standalone Auditing)**
Use this mode to run a targeted, heavy search loop against an endpoint using one of our mathematical exfiltration/jailbreak algorithms.

#### **Example: IKEA Data Reconstruction Attack**
This attack attempts to reconstruct sensitive records (such as database entries) from the target agent's RAG system.
```python
from aginiti.attacks.dra.ikea import IKEAAttack

# 1. Initialize the standalone attack
attack = IKEAAttack(
    target_url="http://localhost:8001/chat",  # Target agent chat endpoint
    llm_provider="groq/llama-3.3-70b-versatile",
    api_key="your_api_key"
)

# 2. Run the exfiltration audit
# topic: the target domain containing sensitive info
# max_queries: query budget to extract and verify data reconstruction
findings = attack.execute_black_box(topic="HR Payroll database", max_queries=20)

# 3. Analyze results
for finding in findings:
    if finding.confirmed:
        print(f" leaked content: {finding.leaked_content}")
        print(f"   Severity: {finding.severity} | Confidence: {finding.confidence}")
```

Other available standalone attacks include:
*   `SECRETAttack` (`aginiti.attacks.dra.secret`): Iterative adversarial jailbreak suffix optimization.
*   `InterrogationAttack` (`aginiti.attacks.mia.interrogation`): Membership Inference Attack to check if specific PII records were used to train or ground the target agent.
*   `SPELLMAttack` (`aginiti.attacks.spe.spe_llm`): System Prompt Extraction audit.

---

### **2. Adaptive Mode (Autonomous Campaigns)**
Use this mode to run the Aginiti Campaign Engine. The planner evaluates the target's security state graph and selects the optimal sequence of reconnaissance and exploitation operators.

#### **Example: Setting up a Campaign**
```python
from aginiti.core.campaign import run_campaign
from aginiti.core.scenarios import multi_path_mission
from aginiti.operators.definitions import build_library
from aginiti.adapters.http_agent_adapter import HTTPAgentAdapter
from aginiti.connectors.endpoint import AgentEndpoint

# 1. Establish a persistent session to the target agent
endpoint = AgentEndpoint(base_url="http://localhost:8001")
agent_adapter = HTTPAgentAdapter(endpoint)

# 2. Configure the audit mission and build the operators
mission = multi_path_mission()
library = build_library()

# 3. Run the campaign loop
result = run_campaign(
    mission=mission,
    library=library,
    agent=agent_adapter,
    max_steps=25
)

# 4. Review the outcome
print(f"Campaign Outcome: {result.outcome}")  # SUCCESS | BUDGET_EXHAUSTED
print(f"Steps executed: {result.steps_executed}")
print(f"Total prompt budget spent: {result.prompts_used}")
```

---

## 🎯 Fine-Tuning the Audit Scope

You can filter the operator library to restrict the campaign to specific types of attacks.

### **Filtering by Security Tier**
Tiers represent broad categories of security posture. You can filter the operator library in Python before launching the campaign:

```python
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.deep_attack_operators import deep_attack_operators
from aginiti.operators.library import OperatorLibrary

# Load all core operators
all_operators = [*data_exposure_operators(), *deep_attack_operators()]

# Example: Filter to only include Data Leakage operators (IKEA, SECRET, MIA, SPE)
data_leakage_operators = [
    op for op in all_operators 
    if op.effects_success and op.effects_success[0].owasp_llm_category in {
        "LLM02_SENSITIVE_INFORMATION_DISCLOSURE", "LLM07_SYSTEM_PROMPT_LEAKAGE"
    }
]

library = OperatorLibrary(data_leakage_operators)
```

### **Filtering by Attack Category**
You can also filter the library by one of the **11 specific attack methodologies** using `.by_category()`:

```python
# Allowed Categories: 
# "direct_prompt_attack", "encoding_attack", "rag_poisoning", 
# "indirect_injection", "tool_discovery", "tool_manipulation", 
# "markdown_network_exfiltration", "multi_step_chain", 
# "decoy", "known_defended", "low_value_reconnaissance"

library = OperatorLibrary(all_operators).by_category("multi_step_chain", "tool_discovery")
```

---

## 🛠️ Troubleshooting Windows Installation

On certain Windows machines, compiling vector databases locally using `chromadb` can trigger an `onnxruntime` or `numpy` DLL loading exception.

If you encounter a `DLL load failed` error, resolve it by installing these compatible binary versions:
```powershell
pip install onnxruntime==1.17.0 numpy==1.26.4
```
Alternatively, bypass local ONNX computation completely by setting up cloud-based embeddings (e.g. `embed_model="openai/text-embedding-3-small"`).

---

## 📊 Result Analysis & Evidence Extraction

After a campaign finishes, you can extract the final security graph claims to generate compliance or vulnerability reports:

```python
# Print verified vulnerabilities discovered during the campaign
for claim in result.ssg.claims:
    print(f"Vulnerability: {claim.key} -> Status: {claim.status.value} (Confidence: {claim.confidence.value})")
```

---

## 🔗 Links & Resources

*   **GitHub Repository:** For local developer setups, starting Docker target containers, or contributing, visit [Aginiti Red-Team GitHub](https://github.com/dev-devneuron/aginiti-redteam).
*   **Detailed Documentation:** Refer to the `docs/` folder in the repository for detailed papers on the Aginiti planning model, evidence classification, and mitigation guides.
*   **Contributors:** [Omer Bin Dawood](https://github.com/OmerBinDawood), [Muhammad Hammad Irfan](https://github.com/MuhammadHammadIrfan)
*   **License:** MIT
