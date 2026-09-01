# aginiti/attacks/spe — System Prompt Extraction Attacks

This package implements **SPE (System Prompt Extraction)** attack modules for `aginiti-redteam`. SPE probes attempt to extract the target agent's system instructions.

> **Authorized use only.** This tooling is intended exclusively for security testing of systems you own or have explicit written permission to test. Do not run attacks against systems without authorization.

---

## Implemented: SPE-LLM Baseline Probes

**Paper:** Das, Amini, Wu, "System Prompt Extraction Attacks and Defenses
in Large Language Models," ICLR 2026 (arXiv:2505.23817).

### What it does

SPE-LLM fires three static adversarial prompt templates designed to jailbreak or guide the model into leaking its system instructions (e.g. system prompts):

1. **Chain-of-Thought (CoT):** Guides the agent through structured thinking stages to print the prompt verbatim.
2. **Extended Sandwich:** Wraps requests for system prompt disclosure around conversational and explainer text to bypass simple keyword blocklists.
3. **Few-Shot:** Provides positive examples of other mock system instructions being correctly printed, training the model to follow the pattern and leak its own prompt.

These are static templates that do not require any online LLM optimization, meaning they execute extremely quickly with zero attacker LLM costs.

### Quick Start

```python
from aginiti.attacks.spe import SPEAttack

attack = SPEAttack(
    target_url="http://localhost:8004",
    # Pass auth tokens or headers if the target requires authentication:
    endpoint_kwargs={
        "headers": {
            "Authorization": "Bearer YOUR_AGENT_KEY"
        }
    }
)

# Run the black-box attack using heuristic indicators to classify leaks
findings = attack.execute_black_box(persona="legal")

for f in findings:
    print(f"Strategy: {f.reasoning}")
    print(f"Confirmed Leak: {f.confirmed} (Severity: {f.severity})")
    print(f"Response snippet: {f.leaked_content[:200]}")
    print("-" * 50)
```

### Benchmarking and Evaluation

If the target's ground-truth system prompt is known, you can evaluate the findings post-hoc to calculate metrics like Exact Match (EM), Subset Match (SM), and cosine similarity:

```python
# Score the findings against the expected ground truth prompt
scored_findings = attack.score_against_ground_truth(
    findings=findings,
    ground_truth_prompt="You are a helpful assistant..."
)

for f in scored_findings:
    # reasoning will contain scored metrics: Strategy=CoT | EM=1 | SM=1 | Cosine=0.9841
    print(f.reasoning)
```
