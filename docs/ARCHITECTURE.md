# Architecture

How Aginiti thinks, plans, and decides what to try next — a genuine planning system
built for autonomous AI red-teaming, not a longer prompt list wearing an agent's clothes.

---

## The core idea

Most red-teaming tools work one of two ways: a **static scanner** fires a fixed list of
payloads and scores pass/fail, stateless, one probe at a time — or a **human operator**
builds up an understanding of the target and improvises a chain by hand.

Aginiti does neither. It treats an assessment as **planning under uncertainty over a
persistent evidence graph**. Every real signal from the target — a tool it revealed, a
trust relationship it exposed, a defense that fired — is recorded as an evidence-linked
claim, and that claim immediately changes what the planner considers trying next. The
graph *is* the model of the target; the plan is derived from it, not scripted in advance.

```
Mission + OperatorLibrary + SecurityStateGraph + Planner + Adapter
        │
        ▼
 1. Planner.rank()      — filter to operators whose preconditions currently hold,
                           enforce hard risk/budget limits, score the rest
        ▼
 2. Operator.render()   — build the actual prompt, substituting in facts already
                           learned (a real tool name, a real identity) — not boilerplate
        ▼
 3. Adapter.send()      — deliver it to the real (or mock) target, get the raw response
        ▼
 4. Observe & judge     — record the raw response, extract confirmed effects
                           (deterministic extractor first, LLM judge otherwise),
                           cross-check against an independent oracle, update the graph
        ▼
 5. Repeat — every claim learned is visible to the next ranking call
```

Nothing is hardcoded about *order*. A capability discovered by operator A can unlock
operator B even if B's author never knew A existed — see [Multi-step discovery](#multi-step-discovery-not-pre-wired-chains) below.

## The evidence model

Five tiers, each more interpreted than the last:

| Tier | What it is |
|---|---|
| **Fact** | The raw, uninterpreted response. Never revised. |
| **Observation** | A verdict linking that raw signal to specific claim keys. |
| **Claim** | The versioned belief itself — `HYPOTHESIZED` / `CONFIRMED` / `REFUTED`, with a confidence band. |
| **Insight** | Synthesized higher-order reasoning (behavioral, security, or knowledge-gap). |
| **Hypothesis** | The one deliberately *mutable* object — a testable prediction that updates in place as evidence arrives. |

A finding never gets to skip this ladder. Nothing counts as "confirmed" on an LLM's
say-so alone — see [Independent verification](BENCHMARKS.md#independent-verification-not-just-an-llm-judge) in the results doc.

## The planner's utility function

`aginiti/core/planner/aginiti_planner.py` scores every eligible operator with a
constrained-utility function, not a bandit heuristic or a fixed priority list:

```
core_utility(op) = α · (info_gain + chain_value)
                  + β · (business_impact + path_progress + emergent_impact + potential_progress)
                  + gap_priority + hypothesis_priority + branch_interest + severity_priority
                  − failure_evidence_penalty

utility(op) = core_utility(op) + family_diversification
                                + hypothesis_escalation_bonus
                                + technique_cluster_diversification
```

Nine terms reason about real, observed evidence: information gain, progress along a
discovered attack path (real BFS over the confirmed graph, not a hardcoded chain),
credit for unlocking a valuable but *unnamed* follow-on compromise, priority from open
knowledge gaps, and a penalty for anything that shares a diagnosed failure pattern with
something already confirmed blocked. Three exploration terms sit outside the core score
and only ever affect *ranking order among eligible candidates*, never eligibility itself
— they push the planner toward genuinely untried attack families and away from
re-sampling near-duplicate wrappers of a question it already answered. Risk tier and
budget are hard constraints throughout, never folded into the score.

The result, measured against real targets, not just claimed: reaching the same or more
attack surface at a fraction of the request budget a fixed enumeration needs — see
[docs/BENCHMARKS.md](BENCHMARKS.md).

## Multi-step discovery, not pre-wired chains

Chains don't have to be authored end-to-end by one person. `ClassPrecondition` gates a
downstream operator on a **semantic tag** — a claim category, an attack methodology, a
minimum security-boundary depth — rather than one exact upstream claim key. Any operator
that happens to produce a matching claim unlocks it, including one written later, by a
different author, for a different subsystem entirely.

Demonstrated with a real 6-step chain: discover capability → establish trust → poison
retrieved context → trigger a tool → reach a sensitive resource → exfiltrate — with two
independently-authored, mutually substitutable "establish trust" operators proving the
discovery is real: delete either one, and the identical downstream chain still completes
through the other, with zero code changes anywhere else in the graph.

## Composite, severity-weighted scoring

A flat success rate treats a system-prompt leak and a confirmed data exfiltration as the
same "1 success." Aginiti's composite score doesn't:

```
score = mission_success × security_boundary × business_impact × cost_efficiency × evidence_quality
```

Multiplicative, on purpose — a campaign that never satisfies its mission scores exactly
`0.0`, full stop, so no other factor can manufacture partial credit for a non-success.
Validated against a graduated-difficulty candidate ladder with ground-truth success rates
hidden from the planner: Aginiti wins the raw success-rate race *less* often than a fixed
baseline in that test, but its wins are worth roughly 2× more on the composite score,
because it commits to the highest-severity candidate first rather than the cheapest and
most likely one.

## The taxonomy layer

Every confirmed finding carries independent tags, each answering a different question:

| Dimension | Answers |
|---|---|
| `category` | What kind of graph fact is this — capability, trust edge, mission outcome, defender control? |
| `security_boundary` | How deep did this go — L0 (model behavior) through L5 (confirmed exfiltration)? |
| `owasp_llm_category` | Which OWASP LLM Top 10 risk? |
| `attack_category` | Which of 11 named attack methodologies? |
| `mitre_atlas_technique` | Which MITRE ATLAS technique (verified ID only)? |
| `technique_cluster` | Is this one of several near-duplicate wrapper variants of the same underlying hypothesis? |

Tags are opt-in and additive — an untagged claim means "not yet classified," never a
fabricated default.

## The attack catalog

Two shapes of operator: **hand-authored** (a fixed library per target family) and
**generated** (built programmatically — one operator per encoding, per pretext, per
external benchmark's own test case, or synthesized live by a search).

| Family | Mechanism |
|---|---|
| **Direct prompt attacks** | System-prompt extraction, jailbreak framings, credential/secret fishing, authority-claim social engineering |
| **Encoding & obfuscation** | Algorithmic ciphers (base64/hex/ROT13/morse/stacked chains), ASCII-art token masking ([ArtPrompt](https://arxiv.org/abs/2402.11753)), low-resource-language jailbreaks, and a live *search* over cipher families rather than a fixed list |
| **Multi-turn escalation** | [Crescendo](https://arxiv.org/abs/2404.01833) (gradual real-turn escalation), [Deceptive Delight](https://unit42.paloaltonetworks.com/) (benign-sandwiched harmful requests), many-shot jailbreaking |
| **RAG poisoning & indirect injection** | Planted documents surviving retrieval and triggering later, unrelated turns; [InjecAgent](https://arxiv.org/abs/2403.02691)'s 1,054 real test cases driven through Aginiti's own campaign loop |
| **Tool & agent exploitation** | Tool-inventory disclosure, parameter-override, MCP auth/registration-poisoning, real 2-step cross-tool composition attacks |
| **Data reconstruction** | IKEA (embedding-space resampling) and SECRET (jailbreak-optimized, [arXiv:2510.02964](https://arxiv.org/abs/2510.02964)) — standalone or planner-selectable |
| **Membership inference** | The [Interrogation Attack](https://arxiv.org/abs/2502.00306) — confirms whether a specific document exists in a target's retrieval corpus via calibrated yes/no probing, no direct extraction needed |
| **RBAC & access-control probing** | Cross-persona authority claims, output-filter evasion, session-isolation, PII-redaction format gaps |

Select any subset directly:

```python
from aginiti.operators.library import OperatorLibrary
library = OperatorLibrary.by_category("encoding_attack", "rag_poisoning")
```

or from the CLI: `python scripts/run_campaign.py --attack-category encoding_attack`.

## Repository layout

```text
aginiti/
├── core/           # Campaign engine: graph, planner, policies, mission, observation
├── operators/       # Attack libraries — one module per target/technique family
├── adapters/        # One adapter per real/mock target — the only place transport lives
├── adaptive/        # Search-based discovery engines (encoding, framing, Crescendo, ...)
├── attacks/         # Standalone attack implementations: IKEA, SECRET, Interrogation
├── connectors/       # HTTP client + embedding routing
└── reporting/        # Markdown/PDF report generation
benchmarks/
├── dev_fixtures/    # Lightweight mock targets for unit tests & local dev
└── scaled_evals/    # Production-scale targets over real document corpora
experiments/         # Live A/B experiment scripts + their results
scripts/             # Entry points — see the README Quickstart
```

## Glossary

| Term | Meaning |
|---|---|
| **SSG** | Security State Graph — the evidence-linked graph everything above reads and writes |
| **Operator** | One attack technique: a prompt template plus its preconditions and success/failure effects |
| **Policy** | A ranking strategy over the operator library — `AginitiPlanner`, or a baseline (`Random`, `Static`) for comparison |
| **Ground truth** | A finding confirmed by an independent, non-LLM check, not just an LLM judge |
| **Security boundary** | How deep a confirmed finding actually went, L0–L5 |

For the full evidence behind every claim in this document — real experiment results,
head-to-head comparisons, and citations — see [docs/BENCHMARKS.md](BENCHMARKS.md). For
what's shipped and what's next, see [docs/ROADMAP.md](ROADMAP.md).
