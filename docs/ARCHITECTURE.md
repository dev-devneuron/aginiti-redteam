# Aginiti — Architecture & Codebase Guide

_Last rewritten 2026-08-13. This is a from-scratch rewrite, not a patched
copy of an earlier version — every section reflects the codebase as it
exists today, verified against the actual source tree, not carried forward
from an older draft._

---

## Executive summary

*Read this section alone and you have the complete shape of the system —
everything below is depth, not new information.*

- **What it is:** an adaptive framework that drives an AI target through a
  standard interface (`BaseAdapter`), accumulates everything it learns into
  a persistent, evidence-linked graph (the **Security State Graph**), and
  uses that accumulated understanding to decide what to try next —
  replacing "run a fixed attack library" with "build a model of this
  specific target, then reason over it."

- **The core data flow:** `Campaign → Planner → Operator → Adapter → Fact →
  Observation → Claim → Insight → Hypothesis → Target Profile report`. A
  planner picks an `Operator` (a formalized probe with declared
  preconditions and predicted effects); an `Adapter` delivers it to the
  real target and returns the raw response; that response becomes a `Fact`
  (raw, uninterpreted), is judged into an `Observation` (evidence for/against
  something), which updates a `Claim` (the current belief, versioned, never
  overwritten); `Claim`s get synthesized into `Insight`s (higher-order
  conclusions) and, where testable, `Hypothesis`es (the one mutable object
  in an otherwise append-only graph). The `Target Profile` renders all of
  it as a report, built from the graph alone — no live campaign required.

- **Codebase shape:** `aginiti/graph/` (the SSG itself), `aginiti/operators/`
  (per-target probe libraries), `aginiti/adapters/` (per-target transport
  integrations), `aginiti/planner/` (the utility-based decision engine),
  `aginiti/policies/` (planner + 4 baselines sharing one campaign loop),
  `aginiti/target_hardening/` (a production-realistic hardened gateway used
  as a target), `aginiti/adaptive/` (search-based attack discovery, a
  separate orchestrator from the main planner), `experiments/` (controlled,
  cited validation of specific claims). Full folder-by-folder breakdown in
  §2–3.

- **How the next probe gets chosen:** a constrained-utility function over
  nine additive terms (§6) — information gain, chain value, business
  impact, real BFS path-progress over the confirmed graph, emergent impact,
  potential-based shaping, priority from open knowledge gaps and
  hypotheses, branch interest, a severity nudge, and a penalty for
  candidates that share a diagnosed failure mode with something already
  confirmed blocked. Risk tier and budget are hard constraints, never
  folded into the same score as predicted value.

- **How chains get discovered, not just followed:** every multi-step chain
  in this project used to be wired by an author hardcoding that operator B
  needs the exact claim key operator A produces. `ClassPrecondition` (§7)
  instead gates an operator on a *semantic tag* — whichever upstream
  operator happens to produce a matching claim unlocks it, including one
  written later by a different author for a different subsystem. This is
  what makes the SSG a genuine discovery substrate instead of a fixed
  script with a graph-shaped memory.

- **Why the abstractions exist:** every concept in this document — Fact as
  distinct from Claim, the Hypothesis object, deterministic extraction,
  `emergent_impact`, `ClassPrecondition`, the category taxonomies — was
  added because a specific real target or a specific controlled experiment
  forced it, not because it seemed useful in advance. §10 maps every
  abstraction to the exact thing that required it, including things
  deliberately *not* built and why.

- **Proven on real targets, not just designed:** six independently-built
  systems integrated to date, four of them still actively exercised. See
  "Is this real, or just a design on paper?" below and
  `docs/EVIDENCE_AND_EVALUATION.md` for citations.

- **Known limitations, stated plainly (§12):** the confidence model is a
  bounded count, not real Bayesian updating; hypothesis resolution uses
  fixed, uncalibrated thresholds; there is no single unified benchmark
  harness — three separate execution paths exist (§4.4); the frozen RQ1
  benchmark hasn't run at a meaningful sample size, blocked on API quota,
  not on design.

- **For definitions of every term used above**, see the Glossary below. For
  what's actually been proven vs. still open, see
  `docs/EVIDENCE_AND_EVALUATION.md`. For where this is headed, see
  `docs/ROADMAP.md`. For the full attack-category taxonomy and adaptive
  discovery mechanics, see `docs/ATTACK_LIBRARY.md`.

---

## New here? Start with this

**The problem.** Organizations are shipping LLM-backed chatbots and agents
into production — customer support, internal tooling, coding assistants —
and these systems have a security-relevant attack surface that doesn't look
like a traditional software vulnerability. There's no buffer overflow to
fuzz for. The attack surface is the conversation itself: prompt injection,
social-engineering the assistant into treating an unverified claim as
authorization, getting it to disclose data across a trust boundary it
should be enforcing, abusing tool-calling to reach unintended actions.
Existing tooling largely falls into two camps — static prompt-injection
scanners running a fixed library of known payloads (garak, PyRIT-style
systematic probing), scored pass/fail, or manual red-teaming that requires
an operator who already understands the target well enough to hand-craft an
attack chain. Neither produces a durable, structured model of *how* the
target actually behaves.

**What Aginiti is.** An adaptive framework that drives a target through a
`BaseAdapter` (`send(channel, prompt) -> SendResult`,
`ground_truth_mission_achieved() -> bool`) and accumulates everything it
learns into a persistent **Security State Graph (SSG)** rather than a
one-shot transcript. Each probe is an `Operator` — a declared precondition/
effect specification plus the concrete prompt or action, tagged with the
`understanding_question` it answers and an optional deterministic
`extractor` for structured responses. A planner (`AginitiPlanner`) selects
the next operator via a constrained-utility function (§6) built from nine
additive terms; risk tier and budget are hard constraints on the candidate
set, never folded into the same scalar as predicted impact.

**The evidence model — five tiers, each more interpreted than the last:**
- **Fact** — a raw, uninterpreted data point (a tool call's literal
  arguments, a response's literal text). Append-only, never revised, and
  recorded regardless of whether anything is later inferred from it.
- **Observation** — a judge's (or a deterministic extractor's) verdict
  linking a raw signal to which claim keys it supports or contradicts.
- **Claim** — the versioned belief itself: `HYPOTHESIZED` / `CONFIRMED` /
  `REFUTED`, with a confidence band derived from accumulated observations,
  and up to five independent taxonomy tags (§8) so cross-target queries
  don't need protocol-specific code.
- **Insight** — synthesized higher-order reasoning across multiple claims:
  `BEHAVIORAL` (what the target does), `SECURITY` (what that implies for
  risk), or `KNOWLEDGE_GAP` (a security-relevant question nothing in the
  graph yet covers, each optionally linked to the specific unexplored
  operator that would close it).
- **Hypothesis** — the one deliberately *mutable* object in an otherwise
  append-only graph: a testable prediction with persistent identity across
  rounds, confidence that steps toward ACCEPTED/REJECTED as resolving
  evidence arrives, so "the model gets revised after every observation" is
  a literal mechanism, not a metaphor.

**Is this real, or just a design on paper?** Real, and independently
verified across six systems, four still active. Vendored/integrated
targets: `damn-vulnerable-llm-agent` (DVLA, a LangChain `create_agent`
pipeline), `damn-vulnerable-ai-agent` (DVAA, a 19-agent fleet spanning
API/MCP/A2A/consensus protocols), the official
`@modelcontextprotocol/server-filesystem` reference implementation over
real stdio MCP transport, **AnythingLLM** (a real, production-shaped
RAG/agent platform — the project's primary live target since exp11),
InjecAgent (1,054 vendored real benchmark test cases, ACL Findings 2024),
and a self-built **hardened gateway** (`aginiti/target_hardening/`) that
resembles a real enterprise deployment's controls. Confirmed findings
include an agent trusting a self-reported identity with zero verification
(DVAA's A2A layer and, via the identical `CATEGORY_TRUST_EDGE` claim
category, its consensus-voting mechanism), an MCP tool executing with no
authentication check, a real multi-step exfiltration chain against
AnythingLLM confirmed by an independent listener log, and — most recently —
a live, mechanistically-traced case where Aginiti's planner discovered a
genuine multi-step compromise that four other planning strategies (Random,
Static, Greedy-Information-Gain, and a real Bayesian Thompson-sampling
bandit) never attempted once across 120 combined trials (`docs/
EXP20_RESULTS.md`). Full citations for every claim are in `docs/
EVIDENCE_AND_EVALUATION.md`; the capability-by-capability confidence labels
and what's next are in `docs/ROADMAP.md`.

## Glossary

Every term used across this document and its companions
(`EVIDENCE_AND_EVALUATION.md`, `ROADMAP.md`, `ATTACK_LIBRARY.md`), defined
once here so it isn't maintained in four places.

**Core system concepts**
- **Security State Graph (SSG)** — the structured, evidence-linked
  belief-state store representing everything Aginiti has learned about a
  target (`aginiti/graph/ssg.py`'s `SecurityStateGraph`). Append-only
  except for `Hypothesis` objects (below); a revised belief creates a new
  version rather than mutating history.
- **Mission** — the current goal, success criteria (a tuple of claim keys),
  budget (in prompts), risk threshold, and constraints for a campaign
  (`aginiti/mission.py`). `success_mode="any"` lets several independent
  compromise types each satisfy the mission; `"all"` requires every
  criterion.
- **Campaign** — one end-to-end execution of the planning loop against a
  target, from mission set to termination (`run_campaign`,
  `aginiti/campaign.py`). Can start from a fresh graph or one reloaded from
  disk, extending prior understanding rather than starting over.
- **Understanding loop** — a separate campaign-loop implementation
  (`run_understanding_loop`, `aginiti/understanding_loop.py`) that
  re-synthesizes Insights after every single probe and never stops early on
  mission success, prioritizing breadth of understanding over speed to one
  compromise. See §4.4 for how this relates to `run_campaign`.
- **BaseAdapter** — the Protocol every target integration implements:
  `send(channel, prompt) -> SendResult` and
  `ground_truth_mission_achieved() -> bool`. The sole boundary between the
  reasoning engine and a target's actual transport — nothing above this
  line is transport-aware.
- **Ground truth** — an adapter's own, independent check of whether a real
  compromise occurred, read from the target's own raw responses, never from
  what the SSG believes. Exists specifically to catch a planner
  hallucinating success.

**The evidence tiers (Fact → Observation → Claim → Insight → Hypothesis)**
— see "New here? Start with this" above for the one-paragraph version of
each; full mechanics in §5.

**Operators and the planner**
- **Operator** — a planner-agnostic, formalized unit of adversarial action:
  preconditions (exact-key and/or class-based, §7), predicted effects
  (`ClaimEffect`s), cost, risk tier, an `understanding_question`, and an
  optional deterministic `extractor` that bypasses the LLM judge entirely
  for already-structured evidence.
- **OperatorLibrary** — a collection of Operators for one target, either
  authored directly or (for runtime-parameterized targets) produced by a
  factory function.
- **`ClassPrecondition`** — a precondition satisfied by *any* current claim
  matching a semantic tag (`category`, `attack_category`, or a minimum
  `security_boundary` rank), instead of one exact claim key. The mechanism
  behind genuine multi-step discovery — see §7.
- **`TargetBeliefState`** (`aginiti/graph/target_belief.py`) — a stateless,
  campaign-level snapshot rebuilt from the SSG's own claims each time it's
  needed, tracking per-`attack_category` and per-`technique_cluster`
  `FamilyStats` (attempted/confirmed-success/confirmed-blocked counts).
  Feeds `family_diversification` and `technique_cluster_diversification`
  — see §6.
- **`technique_cluster`** — an opt-in `Operator` field grouping near-
  duplicate WRAPPER variants of one hypothesis (e.g. 5 authority-claim
  framings of the same question); `None` for the common, untagged case.
  Finer-grained than `attack_category`, which cannot tell "5 wordings of
  one question" apart from "5 genuinely different techniques" — see §6,
  §9, and `docs/EXP29_RESULTS.md`.
- **RiskTier** — `LOW` / `MEDIUM` / `HIGH` / `DESTRUCTIVE`, a hard
  constraint on the candidate set. `DESTRUCTIVE` never auto-runs — there is
  no human-approval loop yet, so the system simply never selects it.
- **AginitiPlanner** — the constrained-utility planner; full formula in §6.
- **Policy** — the interface generalizing `AginitiPlanner` alongside four
  baselines used for comparison: **Random** (uniform among eligible
  operators), **Static-enumeration** (fixed declared order — representative
  of garak/PyRIT-style systematic probing), **Memory-guided** (weighted by
  historical success rate only, no SSG access — representative of the
  AutoRedTeamer mechanism), and **Bayesian** (Thompson-sampling over a
  per-operator Beta posterior, `aginiti/planner/bayesian_planner.py`).

**Reporting and research framing**
- **Target Profile / Behavioral Security Assessment** — the primary product
  artifact (`aginiti/graph/target_profile.py`): everything currently
  understood about a target, built from the graph alone.
- **Security Question** — a question-keyed (not operator-keyed) view over
  the graph: one `understanding_question` from one or more operators, its
  current answer, and confidence.
- **RQ1 / RQ1b** — the project's founding and secondary research questions
  (`analysis_plan.md`, the frozen benchmark protocol against DVLA). RQ1:
  does the SSG-driven planner beat Random/Static/Memory-guided baselines at
  equal or lower cost? RQ1b: which utility term is doing the work? Still
  not run to completion at the frozen protocol's required trial count — see
  `docs/ROADMAP.md`.
- **Composite score** (`aginiti/composite_score.py`) — `mission_success ×
  security_boundary × business_impact × cost_efficiency × evidence_quality`,
  multiplicative, so a campaign that never satisfies its mission scores
  exactly 0.0 regardless of any other factor. Built to answer "which system
  discovers more *consequential* attack paths," a question flat
  attack-success-rate can't answer.

---

## 1. Philosophy and north star

> **Build the world's best system for understanding the real security
> behavior of AI agents through interaction, continuously learning from
> that understanding, and rigorously exploiting confirmed weaknesses.**

Understanding comes first in that sentence on purpose. The Security State
Graph (SSG) — not any single campaign, exploit, or report — is the durable
asset. A campaign is one *consumer* of the graph, alongside analyst
queries, compliance checks, regression tests, and report generation.
Exploitation is a downstream action the graph's beliefs make possible, not
the thing the system exists to produce. "Continuously learning" is the
third pillar, made concrete by the Hypothesis lifecycle and by campaigns
that keep probing past a satisfied mission rather than stopping at first
success.

Concretely, this shows up in the code as:

- `SecurityStateGraph` can be built, saved, reloaded, and queried with **no
  campaign object in scope at all** (`aginiti/graph/queries.py`,
  `aginiti/graph/persistence.py`). A graph outlives the process that built
  it.
- The primary product artifact is the **Target Profile** — a rendered
  Behavioral Security Assessment (`aginiti/graph/target_profile.py`) — not
  a pass/fail exploit log.
- Every operator declares an `understanding_question` before it declares an
  exploit angle. Probes are experiments first, attacks second.
- Evidence is layered — **Fact → Observation → Claim → Insight →
  Hypothesis** — so "what literally happened," "what supports a belief,"
  "what we currently believe," "what that implies," and "what we're still
  testing" are five different, independently-inspectable things, never
  collapsed into one.

A second standing rule, enforced since early in the project: **every new
abstraction must justify its runtime and complexity.** The question asked
before adding any concept is "which currently-integrated target actually
required this?" — never "a future target might need this." §10 catalogs
concrete abstractions and the target that forced each one, alongside
several explicitly-considered, explicitly-rejected additions.

A third rule: **operators are written from publicly documented technique
classes, never reverse-engineered from a target's exact vulnerable source
line.** Source reading is permitted only to build the ground-truth oracle
and adapter plumbing. This keeps Aginiti's findings generalizable claims
about a behavior class, not a fragile match against one implementation
detail.

---

## 2. Directory tree

```
Aginiti-Extended/
├── aginiti/
│   ├── graph/                    Security State Graph: schema, store, reasoning, I/O
│   │   ├── schema.py              Fact / Observation / Claim / Insight dataclasses, id counters
│   │   ├── hypothesis.py          Hypothesis: the one mutable, persistent-identity object
│   │   ├── ssg.py                 SecurityStateGraph: the append-only store + confidence model
│   │   ├── queries.py             Analyst-facing read-only queries over a graph
│   │   ├── target_graph.py        BFS shortest-path reasoning over the confirmed subgraph,
│   │   │                          incl. the semantic hub-node mechanism (§7)
│   │   ├── belief_state.py        CampaignBeliefState: a planner-facing CACHE of derived
│   │   │                          understanding, always reconstructable from the SSG itself
│   │   ├── priors.py              Cold-start context seeding — closes the "every candidate
│   │   │                          scores identically on move 1" gap (see §11)
│   │   ├── insights.py            LLM synthesis: claims -> Behavioral/Security/Knowledge-Gap insights
│   │   ├── target_profile.py      Builds + renders the Behavioral Security Assessment
│   │   ├── persistence.py         SecurityStateGraph <-> JSON on disk
│   │   ├── export.py              SecurityStateGraph -> node-link JSON for visualization
│   │   ├── security_boundary.py   L0-L5 severity taxonomy
│   │   ├── owasp_llm_taxonomy.py  OWASP Top 10 for LLM Applications (2025) taxonomy
│   │   ├── attack_category.py     11-category attack-methodology taxonomy
│   │   ├── mitre_atlas_refs.py    Verified MITRE ATLAS technique cross-references
│   │   ├── failure_diagnosis.py   Structured failure-diagnosis taxonomy (§9)
│   │   └── templates/graph_view.html   Standalone interactive graph viewer
│   │
│   ├── operators/                 Operator framework + per-target operator libraries
│   │   ├── library.py             Operator, ClaimEffect, Precondition, ClassPrecondition (§7),
│   │   │                          OperatorLibrary
│   │   ├── definitions.py         Mock Payroll/Slack/GitHub reference target (21 operators)
│   │   ├── dvla_definitions.py    damn-vulnerable-llm-agent (3 operators)
│   │   ├── dvaa_definitions.py    DVAA memory/A2A/MCP (12 active operators)
│   │   ├── dvaa_consensus_definitions.py   DVAA voting scenario (3 operators)
│   │   ├── mcp_filesystem_definitions.py   Official MCP fs server factory (4 operators)
│   │   ├── anythingllm_definitions.py           RAG document-poisoning chain
│   │   ├── anythingllm_automatic_definitions.py Automatic-mode tool exfiltration chain
│   │   ├── anythingllm_markdown_exfil_definitions.py  Markdown-image exfiltration chain
│   │   ├── anythingllm_multitool_definitions.py Multi-tool composition chain
│   │   ├── data_exposure.py       Target-agnostic pack: prompt extraction, jailbreak, leakage, etc.
│   │   ├── encoding_variants.py   Target-agnostic pack: 12 static encoding-evasion pipelines
│   │   ├── discovery_chain_definitions.py     ClassPrecondition demonstration: 6-step chain
│   │   ├── graduated_difficulty_definitions.py  Composite-scoring demonstration: 5-candidate table
│   │   ├── agentic_primitives_definitions.py    Approval-gate + untrusted-tool-output primitives
│   │   ├── injecagent.py          Single-case operator generator over vendored InjecAgent data
│   │   ├── injecagent_pool.py     Multi-case operator pack reusing injecagent.py unmodified
│   │   └── injecagent_data/       Vendored InjecAgent benchmark data (1,054 test cases, MIT)
│   │
│   ├── adapters/                  BaseAdapter implementations for real/external targets
│   │   ├── base.py                 The BaseAdapter Protocol every target implements
│   │   ├── dvla_adapter.py         damn-vulnerable-llm-agent (LangChain create_agent)
│   │   ├── dvaa_adapter.py         DVAA: API / MCP / A2A / consensus channels, 19-agent fleet
│   │   ├── mcp_stdio_adapter.py    Real stdio-transport MCP servers
│   │   ├── anythingllm_adapter.py  AnythingLLM / the hardened gateway (HTTP REST)
│   │   └── vendor/dvla_transaction_db.py   Vendored copy used only to build ground truth
│   │
│   ├── adapter/                   (singular — historical name, kept as-is)
│   │   └── observation_adapter.py  Operator execution -> Fact + Observation + Claim(s);
│   │                                the exception-safe choke point every execution passes through
│   │
│   ├── target/                    Self-built reference/regression targets
│   │   ├── demo_agent.py           Mock agent: Groq-backed tool-calling loop
│   │   └── tools.py                Mock Payroll/GitHub/IT-Helpdesk tools + suspicion state
│   │
│   ├── target_hardening/          A self-built, production-realistic hardened gateway (docs/HARDENED_TARGET.md)
│   │   ├── gateway_server.py       The gateway itself: auth tiers, approval gate, audit log
│   │   └── policy.py               Document sanitization, output redaction, rate limiting,
│   │                                adaptive suspicion-based lockout
│   │
│   ├── static_analysis/
│   │   └── prompt_defense.py       Adapted from Cisco's mcp-scanner (Apache 2.0) — regex-based
│   │                                prompt-injection defense-rule detection
│   │
│   ├── transforms/
│   │   └── converters.py           Composable PromptConverter pipeline (PyRIT-inspired)
│   │
│   ├── adaptive/                   Search-based attack discovery — a separate orchestrator,
│   │   │                            not wired into AginitiPlanner (see §4.4/§11)
│   │   ├── variant_discovery.py    Generic engine: try candidates until one succeeds or budget runs out
│   │   ├── encoding_discovery.py   Searches the encoding-pipeline space (CipherChat/MetaCipher-inspired)
│   │   ├── framing_discovery.py    Searches social-engineering pretexts, escalates to refinement.py
│   │   └── refinement.py           PAIR-style (Chao et al. 2023) single-operator retry loop
│   │
│   ├── planner/
│   │   ├── aginiti_planner.py      The constrained-utility planner (§6)
│   │   ├── bayesian_planner.py     Thompson-sampling planner variant
│   │   └── variants.py             Pure-parameterization planner variants (GreedyInfoGain,
│   │                                GreedyBusinessImpact, BFSOnly) for RQ1b
│   │
│   ├── policies/                   Policy = Planner adapted to the shared campaign-loop interface
│   │   ├── base.py                 Policy Protocol, eligible_operators() (shared substrate)
│   │   ├── aginiti_policy.py       AginitiPlanner wrapped as a Policy
│   │   ├── bayesian_policy.py      BayesianPlanner wrapped as a Policy
│   │   ├── random_policy.py        Floor baseline
│   │   ├── static_policy.py        Fixed-order enumeration baseline
│   │   └── memory_guided_policy.py Attack-outcome-memory baseline (no SSG access)
│   │
│   ├── campaign.py                 The generic campaign loop (any Policy, any BaseAdapter)
│   ├── understanding_loop.py       Plan -> Execute -> Learn -> Repeat, insight-synthesis-in-the-loop
│   ├── mission.py                  Mission: goal, success criteria, budget, risk threshold
│   ├── scenarios.py                Shared Mission definitions (one per target)
│   ├── benchmark.py                4-condition benchmark harness, resumable (mock target only — see §4.4)
│   ├── composite_score.py          Severity-weighted campaign scoring (multiplicative, §6)
│   ├── report.py                   Loads runs/<id>/*.json -> summary + stats
│   ├── stats.py                    Dependency-free Fisher's exact test
│   ├── pdf_export.py               HTML report -> PDF via headless Chrome/Edge
│   ├── logging_utils.py            JSON-safe serialization, persistent per-trial logging
│   ├── observability.py            Library-standard structured logging (NullHandler by default)
│   ├── llm_client.py               Groq wrapper: chat / chat_json / chat_tools, multi-key rotation
│   └── gemini_client.py            Gemini-backed client, used to route around Groq quota exhaustion
│
├── scripts/                        Runnable entry points
├── experiments/                    38 controlled/live experiment scripts, each a self-contained
│                                   validation of a specific claim (see docs/EVIDENCE_AND_EVALUATION.md)
├── tests/                          837 offline unit tests, no live API/network calls (pytest.ini
│                                   scopes discovery to this directory only)
├── runs/                           Per-run JSON logs, generated reports, saved graphs (gitignored)
├── targets/                        Vendored third-party target applications (gitignored — see
│                                   docs/INFRASTRUCTURE.md)
├── infra/                          This project's own operational scripts/logs (gitignored)
├── analysis_plan.md                FROZEN RQ1 benchmark protocol — do not edit after trials begin
├── docs/                           This file and its companions (see the index at the end of
│                                   docs/AGINITI_OVERVIEW.md)
└── requirements.txt
```

---

## 3. What every top-level folder is for

| Folder | Role |
|---|---|
| `aginiti/graph/` | The SSG itself: data model, store, reasoning queries, synthesis, I/O, and every taxonomy dimension. This is the asset everything else serves. |
| `aginiti/operators/` | The **content** layer — what Aginiti can actually try against a target, per target or target-agnostic. Operators are data (dataclasses), not code paths; adding a target should not require touching the planner or graph. |
| `aginiti/adapters/` (plural) | The **real-target** integration layer. One class per external system, implementing `BaseAdapter`. This is the only place that knows a target's actual wire protocol. |
| `aginiti/adapter/` (singular) | One file: the bridge between an operator execution and the graph, and the single exception-safety choke point every execution passes through. Deliberately named/organized differently from `adapters/` (historical — kept because a mechanical rename wasn't worth the churn). |
| `aginiti/target/` | Self-built reference targets, kept only as a fast, free, deterministic regression fixture — never scored as evidence for a research question once a real target exists. |
| `aginiti/target_hardening/` | A self-built gateway that sits in front of AnythingLLM and adds the controls a real enterprise deployment would have, so live experiments test against a realistic, defended target instead of a soft one. |
| `aginiti/adaptive/` | Search-based discovery (7 modules — encoding/many-shot/framing discovery, PAIR refinement, Crescendo escalation, membership inference) for attack families where a fixed operator list genuinely isn't the right shape. Its own ranking loop stays separate from the main planner (see §11), but `aginiti/assessment.py`'s `run_full_assessment()` (2026-08-14) now runs it and `AginitiPlanner` SEQUENTIALLY over one shared graph — see §4.4. |
| `aginiti/planner/` | The reasoning that picks the next operator. `AginitiPlanner` is the main class; `variants.py` and `bayesian_planner.py` hold comparison baselines that share its structure but not its full formula. |
| `aginiti/policies/` | The abstraction that lets five different "who picks next" strategies drive the identical campaign loop, so a benchmark comparison isolates the policy and nothing else. |
| `scripts/` | Thin, runnable entry points. No logic lives here that isn't in `aginiti/` — a script wires objects together and prints/writes output. |
| `experiments/` | Controlled and live validation of specific claims, each a self-contained script with a stated hypothesis, baseline, and metric — see `docs/EVIDENCE_AND_EVALUATION.md` §0. |
| `tests/` | Pure-Python, offline. Every LLM call and every network call is mocked; nothing here costs tokens or requires a running server. |
| `runs/` | Generated artifacts: benchmark trial JSON, HTML/PDF reports, saved graphs, rendered Target Profiles. Gitignored — reproducible from source + a live run. |
| `targets/`, `infra/` | Vendored third-party target applications and this project's own operational scripts/logs respectively — both gitignored, both fully described in `docs/INFRASTRUCTURE.md`. |
| `docs/` | This guide and its companions — the living documents referenced from every planning conversation about what to build next. |

---

## 4. End-to-end execution flow

### 4.1 The shared pipeline, one operator execution at a time

```
Mission + OperatorLibrary + SecurityStateGraph + Policy/Planner + BaseAdapter
        │
        ▼
 1. Policy.rank() / Planner.rank()
        — filters library.candidates(ssg) to operators whose preconditions
          currently hold — exact-key AND/OR ClassPrecondition (§7)
        — filters further via eligible_operators(): risk tier <= mission
          threshold, cost <= budget remaining, not already executed
        — scores survivors (Aginiti: the 9-term utility function, §6;
          baselines: random / fixed-order / success-rate-weighted / Thompson
          sampling)
        — returns a ranked list; step 2 takes candidate #1
        ▼
 2. Operator.render_prompt(ssg)
        — substitutes {template_var} placeholders with specific facts
          already learned, falling back to a generic phrase if none yet
        ▼
 3. ObservationAdapter._send(agent, channel, prompt)
        — wraps BaseAdapter.send() in a try/except that converts ANY
          exception (timeout, connection error, malformed response) into
          a SendResult(is_synthetic=True) instead of crashing the campaign
        ▼
 4. ObservationAdapter.execute()
        a. ssg.record_fact(...)              <- raw response text, tool calls,
                                                  recorded before interpretation,
                                                  regardless of what's inferred
        b. is_synthetic? skip interpretation entirely — a target-side
             failure can never be misread as a real success OR a real
             defender-control finding
           operator.extractor is not None? -> deterministic extractor(raw_text)
           else                             -> LLM judge (_judge(), chat_json)
        c. ssg.record_observation(...)        <- links raw_signal to the
                                                  claim keys it supports/contradicts
        d. ssg.assert_claim(...) per confirmed effect
                                                <- new Claim version, tagged with
                                                  up to 5 taxonomy dimensions (§8)
                                                <- SSG._update_hypotheses_for_claim()
                                                  fires here
        e. ssg.record_operator_execution(...)  <- one-shot-per-operator bookkeeping
        ▼
 5. (understanding_loop.py only) synthesize_insights(ssg, ...)
        — re-synthesizes BEHAVIORAL / SECURITY / KNOWLEDGE_GAP insights from
          the graph's full current claim set (LLM call)
        — a KNOWLEDGE_GAP with a prior_belief and a matched, CONFIRMED-capable
          operator becomes a new Hypothesis (ssg.form_hypothesis)
        ▼
 6. loop back to step 1 — every claim, insight, and hypothesis update from
    this iteration is visible to the next ranking call
```

### 4.2 `run_campaign` (`aginiti/campaign.py`)

The loop the frozen RQ1 benchmark measures, and the loop every live
`experiments/expNN_*.py` script drives directly. Runs steps 1–4 above,
`max_steps` times or until the mission is satisfied (`stop_on_mission_success`,
default `True`) or the library/budget is exhausted. Generic over `Policy` —
the exact same loop mechanics drive all 5 benchmark conditions (Random,
Static, Memory-guided, Bayesian, Aginiti); only which `Policy` is passed in
varies. `ssg` can be a fresh graph or one reloaded from disk, so a campaign
can extend a graph a previous session already built.

### 4.3 `run_understanding_loop` (`aginiti/understanding_loop.py`)

One probe per round, always picked by `AginitiPlanner` (not swappable —
this loop isn't part of the RQ1 ablation), immediately followed by insight
re-synthesis (step 5 above) before the next round's ranking happens. This
is what makes gap-driven planning real: a knowledge gap discovered in round
2 can change which operator gets picked in round 3, because `gap_priority`
and `hypothesis_priority` are terms in the same utility function as
information gain and business impact. Stops when no eligible operator has
positive utility left, or `max_rounds` is hit. Never stops early on mission
success — the point is to keep learning past a satisfied mission, not to
exit the instant the exploit lands.

### 4.4 Four parallel execution paths — a real architectural characteristic, not a defect to hide

An independent, from-scratch audit of the codebase (`docs/
ENGINEERING_HARDENING_PASS.md`) traced every real entry point and found
**there is no single, unified benchmark harness**:

```
scripts/run_campaign.py, scripts/run_benchmark.py ──> aginiti/benchmark.py (mock target only)
20+ experiments/expNN_*.py                        ──> hand-rolled trial loops, call run_campaign() directly
scripts/run_*_understanding_loop.py               ──> aginiti/understanding_loop.py (a 2nd loop reimplementation)
experiments/exp20_discovery_arm.py                ──> aginiti/adaptive/*.py directly (never touches AginitiPlanner)
experiments/exp25/exp26_*_live.py (2026-08-14)    ──> aginiti/assessment.py's run_full_assessment() ──>
                                                        adaptive/*.py phases THEN AginitiPlanner, same shared SSG
```

`aginiti/benchmark.py` is real, tested, and correct — but only
`scripts/run_benchmark.py` ever calls it, and it only knows the mock
`DemoAgent` target. Every live-target result this project has ever reported
(exp11 through exp20 — AnythingLLM, DVAA, InjecAgent) came from a bespoke
`expNN_*.py` script that reimplements its own trial loop, condition
builder, and per-trial logging, because each live experiment genuinely
needed different scope-shaping (different libraries, different missions,
different conditions). This is not incidental technical debt so much as a
real property of how the project grew — but it means a fix made to one
loop's error handling does not automatically apply to the other two paths.
The exception-safety fix at `ObservationAdapter._send()` (step 3 above) is
the one recent fix that genuinely does propagate everywhere, because all
three paths funnel through `ObservationAdapter` regardless of which loop
called it.

**Updated 2026-08-14 — this was true, and no longer is, for one of the
three paths.** `aginiti/assessment.py`'s `run_full_assessment()` is a
FOURTH entry point, added specifically to close this gap: it runs
`aginiti/adaptive/*.py`'s engines (encoding discovery, many-shot discovery,
framing discovery + PAIR refinement, Crescendo escalation) IN SEQUENCE
against one shared `SecurityStateGraph`, then hands that SAME graph to a
normal `run_campaign()` + `AginitiPlanner` phase as its final step. A claim
confirmed by any discovery phase IS a real Claim in the graph
`AginitiPlanner`'s campaign phase reads (`TargetBeliefState.from_ssg()`,
`family_diversification`, `hypothesis_escalation_bonus` all see it) — it
is completely indistinguishable to the planner from one confirmed by an
ordinary operator. This does NOT collapse the three-path characteristic
below into one unified harness (`aginiti/benchmark.py`/hand-rolled
`expNN_*.py` scripts/`understanding_loop.py` remain genuinely separate,
for genuinely separate reasons) — it specifically closes the ONE gap that
was a real, tracked limitation rather than an intentional design choice.
Live-verified: `exp25`/`exp26` (`experiments/exp2{5,6}_full_assessment_
vs_baseline_live.py`) run this exact path against `hardened_agent`.

None of this is dead code — all four paths are reachable, tested, and used
to produce real, cited results (§12 has the honest list of what each path
can and can't currently claim).

**A fifth characteristic, added by the two-developer merge (2026-08-20)
rather than by this project's own execution-path work: standalone
single-attack scripts alongside a planner-integrated Operator bridge.**
`scripts/run_ikea.py`/`run_secret.py`/`run_interrogation.py` (and their
`_hardened` variants targeting `hardened_agent` specifically) call a
`BaseAttack` subclass's `execute_black_box()` DIRECTLY — no SSG, no
planner, no `run_campaign()` at all. This is not the same gap the four
paths above describe (those all reach the SAME evidence graph through
different loops); these scripts never touch the graph. **When to use
which, stated plainly rather than left to guess:**
- **A standalone script** — running ONE specific technique against ONE
  target, with tight per-run budget/cost control and output comparable to
  the technique's own paper (`docs/benchmarking.md`'s whole reason for
  being). The right tool for "how effective is IKEA specifically, at N
  queries, against this corpus."
- **`deep_attack_operators()` / `hardened_deep_attack_operators()` via a
  campaign** — letting `AginitiPlanner` decide WHETHER and WHEN an
  expensive, slow, multi-query deep attack is worth its budget relative to
  every other operator available, using the same evidence-driven ranking
  (including `family_diversification`/`technique_cluster_diversification`)
  every other operator is subject to. The right tool for "what's the best
  use of an N-prompt budget against this target, when IKEA/SECRET/MIA/SPE
  are options alongside 40+ cheaper probes." This is the ONLY execution
  path where a deep attack competes for budget against ordinary operators
  rather than running in isolation — see `docs/EXP29_RESULTS.md`'s
  successor experiment for the first live run of this combination.

### 4.5 Report generation

`build_target_profile()` (`aginiti/graph/target_profile.py`) reads a
`SecurityStateGraph` plus the `OperatorLibrary` and `Mission` that produced
it — nothing else, no campaign object — through the analyst queries in
`aginiti/graph/queries.py`, and assembles a `TargetProfile` dataclass.
`render_markdown()` turns that into the Behavioral Security Assessment:
probe coverage, security questions, Behavioral insights, Security insights,
Knowledge gaps, Hypotheses, Capabilities, Trust relationships, Tool
behavior, Observed defenses, Reachable actions, Unverified claims,
Disproven assumptions, Unexplored frontier, and Recommended next probes,
now including every taxonomy dimension's summary. The same function
produces the same report whether the graph came from a run seconds ago or
was reloaded from a `.json` file written days earlier.

The separate benchmark report (`aginiti/report.py` +
`scripts/generate_report.py`) is a different artifact: it compares policy
conditions' trial logs, not a single target's accumulated understanding —
see `analysis_plan.md`.

---

## 5. How evidence flows through the system

```
   Target's raw response / tool call
              │
              ▼
   ┌─────────────────┐   append-only, no interpretation
   │      Fact        │   "a tool was called with these literal args";
   │  (schema.py)      │   "the target emitted this literal text"
   └────────┬─────────┘
            │  judge or deterministic extractor interprets the Fact
            │  (skipped entirely if the send itself failed — is_synthetic)
            ▼
   ┌─────────────────┐   append-only; links a raw signal to claim keys
   │   Observation     │   it supports/contradicts
   │  (schema.py)      │
   └────────┬─────────┘
            │  ssg.assert_claim() creates a new version; confidence is
            │  recomputed from every Observation ever linked to this key
            ▼
   ┌─────────────────┐   append-only; "current" = latest version by key
   │      Claim        │   status: HYPOTHESIZED / CONFIRMED / REFUTED
   │  (schema.py)      │   confidence: LOW / MEDIUM / HIGH (bounded net count)
   │                   │   up to 5 taxonomy tags (§8)
   └────────┬─────────┘
            │  synthesize_insights() reads the full current claim set
            ▼
   ┌─────────────────┐   append-only; grounded in specific claim keys
   │     Insight        │   (BEHAVIORAL/SECURITY) or points at an unexplored
   │  (schema.py)      │   operator (KNOWLEDGE_GAP)
   └────────┬─────────┘
            │  a KNOWLEDGE_GAP with a prior_belief + matched, resolvable
            │  operator becomes a Hypothesis (get-or-create)
            ▼
   ┌─────────────────┐   MUTABLE — the one exception to append-only.
   │   Hypothesis       │   Same object updates in place as more Claims
   │ (hypothesis.py)   │   resolve against its target_claim_key, via
   └──────────────────┘   ssg.assert_claim() -> _update_hypotheses_for_claim()
```

Facts and Claims are deliberately **not equal citizens**: a Fact never has a
status or confidence, because it isn't a conclusion — only Claims are. This
is what lets the graph answer "what did we literally see" independent of
"what did Aginiti conclude from it." Claims, Observations, Facts, and
Insights are all append-only — a revised belief creates a new version
rather than mutating the old one, so the graph's history is always
reconstructable. `Hypothesis` is the sole, deliberate exception: without a
stable, mutable identity, "accept" or "reject" has no referent to act on
(see §10).

---

## 6. How the planner decides the next probe

`AginitiPlanner.rank()` (`aginiti/planner/aginiti_planner.py`) computes,
for every operator whose preconditions currently hold and that hasn't
already run:

```
core_utility(op) = alpha * (information_gain(op) + chain_value(op))
                  + beta  * (business_impact(op) + path_progress(op)
                             + emergent_impact(op) + potential_progress(op))
                  + gap_priority(op) + hypothesis_priority(op)
                  + branch_interest(op) + severity_priority(op)
                  + failure_evidence_penalty(op)

utility(op) = core_utility(op) + family_diversification(op)
                                + hypothesis_escalation_bonus(op)
                                + technique_cluster_diversification(op)
```

Nine evidence-grounded terms make up `core_utility`, in the order they
were added to the codebase:

- **`information_gain`** — sum of per-effect weights over predicted claim
  keys not yet resolved. A claim already confirmed/refuted has no
  information left to gain.
- **`business_impact`** — fraction of currently-unmet mission
  success-criteria this operator's success effects would satisfy.
- **`path_progress`** — real BFS graph reasoning (`target_graph.py`), not
  flat key-matching: builds the currently-CONFIRMED subgraph, asks whether
  hypothetically adding this operator's `graph_edge` shortens or newly
  creates a path to any mission-target node.
- **`gap_priority`** — sums importance-weighted contributions from every
  open `KNOWLEDGE_GAP` insight whose `related_probe_id` names this
  operator. The literal mechanism by which synthesized understanding
  reshapes planning.
- **`hypothesis_priority`** — sums `Hypothesis.uncertainty`-weighted
  contributions from every OPEN hypothesis that lists this operator as one
  of its `experiments`. `uncertainty` peaks at confidence 0.5 (maximally
  informative to test).
- **`emergent_impact`** — the same BFS mechanism as `path_progress`, but run
  against every claim key any operator in the library itself tags
  `mission_outcome`-category, not only the ones a human named in
  `Mission.success_criteria` up front. Closes a real gap found by a
  controlled experiment: without it, an operator that unlocks a genuinely
  valuable but *unnamed* follow-on compromise was indistinguishable from a
  dead end (see `docs/EVIDENCE_AND_EVALUATION.md`).
- **`chain_value`** — a plant operator gets discounted (0.5×) credit for its
  declared downstream trigger's own value, grounded in potential-based
  reward-shaping theory (Ng, Harada & Russell 1999; Wiewiora, Cottrell &
  Elkan 2003 — see `docs/RESEARCH_AND_PROVENANCE.md`). Closes a real bug:
  before this term existed, a multi-step plant operator was structurally
  incapable of ever outranking a mediocre single-step decoy, regardless of
  the chain's real downstream value.
- **`potential_progress`** — a separate potential-based shaping term feeding
  the same theoretical guarantee (a shaping term guaranteed not to distort
  the optimal policy).
- **`branch_interest`** — real, tested, empirically rare to be the deciding
  factor on typical campaigns — reweights toward branches of the mission
  that haven't been explored yet.
- **`severity_priority`** — an unscaled additive nudge toward higher
  `security_boundary` (L0–L5) findings, the planner's first awareness of
  finding *severity*, not just claim resolution.
- **`failure_evidence_penalty`** — a negative, bounded, additive nudge: if a
  CONFIRMED failure claim anywhere in the graph carries a **generalizable**
  `failure_diagnosis` tag (`blocked_by_privilege`, `blocked_by_network_
  egress`, `blocked_by_approval_gate` — see §9) and a candidate operator's
  own prospective failure would carry the identical tag, that candidate is
  demoted. Reuses `ClassPrecondition`'s exact tag-matching idea (§7),
  applied to negative instead of positive evidence.

Three further terms are opt-in EXPLORATION nudges (`aginiti/graph/
novelty.py`), all default `False`/off so an unparameterized
`AginitiPlanner()` is byte-identical to every version of this class before
they existed, and all kept structurally OUTSIDE `core_utility` — see the
"structural invariant" callout below for why that separation is load-
bearing, not cosmetic:

- **`family_diversification`** — `TargetBeliefState.FamilyStats.looks_
  saturated` (2+ CONFIRMED same-`attack_category` outcomes, zero
  successes) demotes a family that looks like a dead end; a family that
  has ever produced one real success can never look saturated again, by
  design, so a working technique is never abandoned. A genuinely untried
  family (`attempted == 0`) earns a bonus two ways: reactively
  (`DIVERSIFICATION_BONUS = 2.5`, if a SIBLING family already looks
  saturated) and, since 2026-08-14, proactively (`PROACTIVE_COVERAGE_
  BONUS = 1.0`, unconditionally) — the proactive half closes a real gap a
  live postmortem found (`docs/EXP29_RESULTS.md`): once ANY family had one
  success, nothing previously gave the planner a reason to also sample a
  completely different family, no matter how many of that first family's
  own untried variants remained.
- **`hypothesis_escalation_bonus`** — rewards a `ClassPrecondition`-gated
  operator whose eligibility just opened up from a claim confirmed
  RECENTLY (within a `recency_window` of the campaign's own length), not
  one that has sat eligible for a while — makes genuine, discovered chain
  continuation an explicit ranking preference, not just something that
  merely becomes possible.
- **`technique_cluster_diversification`** (2026-08-14, `docs/EXP29_
  RESULTS.md`) — a FINER-grained sibling of `family_diversification`,
  closing a gap that mechanism cannot see by construction: `attack_
  category` (11 broad categories) cannot tell "5 near-duplicate wrapper
  templates around one question" (e.g. `hardened_agent_definitions.py`'s
  `_build_authority_claim_probes`) apart from "a genuinely different
  technique that happens to share the same broad category." An author
  opts an operator into a shared `Operator.technique_cluster` string
  (default `None` — a true no-op for every untagged operator, the common
  case); repeating a cluster earns an escalating penalty from the FIRST
  repeat onward, capped at `MAX_CLUSTER_PENALTY = 3.0`. Deliberately **NOT
  success-immune**, the one place this term's shape differs on purpose
  from family-level saturation: a cluster is variants of ONE hypothesis,
  so confirming it once genuinely diminishes the value of asking the same
  question a 3rd/4th/5th way — unlike a family, which legitimately
  contains many different ideas a single success must never demote.

`alpha`/`beta` follow a fixed schedule: `alpha` decays and `beta` rises as
`prompts_used / budget` grows — early in a campaign, learn; late in a
campaign, close out mission-relevant paths.

**Structural invariant (2026-08-14, exp23 postmortem fix) — the
feasibility gate reads `core_utility` alone, never the three exploration
terms.** `rank()` drops a candidate only when `core_utility(op) <= 0` —
genuinely no evidence-based value left, independent of exploration. The
three exploration terms can only ever influence WHERE a surviving
candidate sorts (even pushing its final `utility` negative), never WHETHER
it survives at all. Before this fix, the gate tested the FULL summed
`utility`, so `family_diversification`'s bounded saturation penalty (then
capped at -3.0) could push an otherwise-viable candidate below zero and
silently remove it from the ranked list entirely — exactly the "informs,
never vetoes" contract `novelty.py`'s own docstring states, and the
confirmed live cause of a real `SEARCH_EXHAUSTED`-with-budget-remaining
failure (3/3 campaigns, 15-16 of 24 operators still untried each time).
Fixing this also restored principled exploration for free: once every
currently-favored candidate is executed or genuinely infeasible, the
next-best SURVIVING candidate — even one from a "saturated" family — rises
to the top of what's left, instead of the campaign reporting exhaustion
while real candidates remain.

Risk tier and budget remain **hard constraints** on the candidate set
(`eligible_operators` in `aginiti/policies/base.py`), never penalty terms
folded into the same scalar as business impact — a large predicted impact
must never numerically outweigh a disallowed risk tier. The baseline
policies (Random, Static, Memory-guided, Bayesian) share the exact same
`eligible_operators()` gate, so a benchmark comparison isolates *ranking
strategy* and nothing else. The three pure-parameterization variants in
`aginiti/planner/variants.py` (`GreedyInfoGainPlanner`,
`GreedyBusinessImpactPlanner`, `BFSOnlyPlanner`) reuse the identical
formula with specific terms hard-zeroed, for isolating which term does the
work (RQ1b).

---

## 7. Multi-step discovery: `ClassPrecondition` and semantic hubs

Every multi-step chain in this project prior to `ClassPrecondition` was
wired with `Precondition(key, status)` — an author hardcoding that operator
B requires the *exact* claim key operator A produces. Aginiti could pivot
between such chains correctly, but could never attempt a step sequence a
human hadn't pre-declared key-for-key. Two pieces close that gap:

1. **`ClassPrecondition`** (`aginiti/operators/library.py`) — a
   precondition satisfied by *any* currently-current claim matching a
   **semantic class**: `category`, `attack_category`, and/or a minimum
   `security_boundary` rank — all three are established, independently-
   maintained taxonomy dimensions every `ClaimEffect` already carries (§8),
   not new machinery. `Operator.precondition_classes` is ANDed with the
   existing exact-key `preconditions` tuple. A downstream operator gated
   this way is unlocked by *whichever* upstream operator happens to produce
   a matching claim — including one written later, by a different author,
   for a different subsystem.

2. **Semantic hub nodes** (`aginiti/graph/target_graph.py`) —
   `category_hub()`, `attack_category_hub()`, `boundary_hub()`. Every
   confirmed effect with a matching tag gets an edge into the matching hub,
   wired from the library/SSG's own tag metadata — never from a
   per-operator declaration naming another operator. A `ClassPrecondition`-
   gated operator declares its own `graph_edge` starting **from** the hub.
   Because `path_progress`, `emergent_impact`, `potential_progress`,
   `chain_value`, and `budget_feasible` in `aginiti_planner.py` all consume
   `build_graph()` as an abstract adjacency list — never `Operator.
   preconditions`/`graph_edge` directly — **every one of those terms gained
   the ability to reason over a discovered, non-hardcoded chain with zero
   changes to that module.**

Hub traversal is bookkeeping, not a real operator execution, so hub edges
cost 0 in the planner's distance heuristics while every real operator edge
costs 1 (a proper **0-1 BFS**, `shortest_distances`/
`distance_to_nearest_target`) — an earlier version of this change
double-counted hub hops as real steps, wrongly pruning a genuinely
completable class-gated chain as infeasible; caught by the composite-
scoring test suite before it ever touched a live target.

**Demonstrated with a real 6-step chain**
(`aginiti/operators/discovery_chain_definitions.py`), matching the
project's own founding example verbatim: *discover capability → establish
trust → poison retrieved context → trigger tool → reach sensitive resource
→ exfiltrate*. Every operator past stage 1 has an empty exact-key
`preconditions` tuple — all gating past stage 1 is `ClassPrecondition`-only.
Two independently-written, mutually-substitutable "establish trust"
operators prove the discovery is real: delete either one, the identical
downstream chain still completes through the other, with zero code changes
anywhere else. Reused a second time, independently, for the agentic-
primitives pack (§9) as a cross-check that the mechanism generalizes rather
than being overfit to its original demonstration.

---

## 8. The taxonomy layer — five independent dimensions

Every confirmed finding can carry up to five tags, each answering a
different question, threaded through `ClaimEffect` → `SecurityStateGraph` →
`ObservationAdapter` → the Target Profile report → the visualization
export → trial-log serialization:

| Dimension | Answers | Module |
|---|---|---|
| `category` | What KIND of graph fact is this? (capability / trust_edge / mission_outcome / defender_control / workflow) | `ssg.py` |
| `security_boundary` | How deep did this go, if real? (L0 model behavior → L5 confirmed exfiltration) | `security_boundary.py` |
| `owasp_llm_category` | Which OWASP LLM Top 10 (2025) risk? | `owasp_llm_taxonomy.py` |
| `attack_category` | Which of 11 named attack methodologies? (8 offensive + 3 planner-evaluation controls: decoy/known-defended/low-value-recon) | `attack_category.py` |
| `mitre_atlas_technique` | Which MITRE ATLAS technique (verified ID only)? | `mitre_atlas_refs.py` |
| `failure_diagnosis` | *(on failure effects only)* Why did this fail, and is that evidence about other operators too? | `failure_diagnosis.py` |

Opt-in and additive throughout — an untagged claim means "not yet
classified," never a fabricated default. `category` is the oldest
dimension and the one every operator in the codebase carries; the rest
were retrofitted onto the existing library incrementally, so coverage
varies by target (newer targets and target-agnostic packs carry more tags
than the oldest ones). See `docs/ATTACK_LIBRARY.md` for the full category
table and `docs/RESEARCH_AND_PROVENANCE.md` for where each taxonomy comes
from.

---

## 9. How operators are structured

An `Operator` (`aginiti/operators/library.py`) is a frozen dataclass — data,
not a code path:

| Field | Purpose |
|---|---|
| `preconditions` | Exact claim-key/status pairs that must hold before this operator is even eligible |
| `precondition_classes` | `ClassPrecondition`s (§7) — semantic-tag-based, ANDed with `preconditions` |
| `effects_success` / `effects_failure` | *Predicted* claim-key deltas (`ClaimEffect`s, each optionally carrying all 5 taxonomy tags) — the Observation Adapter reconciles these against what the target actually did |
| `channel` | Which adapter-specific delivery surface to use (`"direct"`, `"slack"`, `"api:legacybot"`, `"mcp:filesystem"`, `"consensus:voting"`, ...) |
| `understanding_question` | What this probe teaches, independent of whether it also lands as an exploit |
| `extractor` | Optional deterministic bypass for the LLM judge |
| `graph_edge` | `(from_node, to_node)` — what confirming this operator's success means structurally, feeding `target_graph.py`'s path reasoning; may originate from a semantic hub instead of a named node |
| `template_vars` | `{prompt_placeholder: claim_key}` — lets a prompt reference a fact actually learned earlier |
| `risk_tier`, `cost_prompts` | Hard constraints the planner enforces |
| `technique_cluster` | (2026-08-14, opt-in, default `None`) A shared string an author declares for a set of near-duplicate operator WRAPPERS around one hypothesis (e.g. 5 authority-claim framings of the same question) — feeds `technique_cluster_diversification` (§6). Never inferred, never guessed onto operators an author hasn't actually verified share a mechanism — see `docs/EXP29_RESULTS.md` for a real example (`redaction_format_evasion.py`) of a candidate cluster deliberately left untagged after inspection showed the members are genuinely distinct techniques. |

An `OperatorLibrary` is a dict-backed collection with `.candidates(ssg)`
(precondition filtering, both exact-key and class-based) and `.get(id)`.
Most targets export a no-argument `build_X_library()`. Two targets are
factory-shaped instead: the MCP filesystem target (`build_filesystem_mcp_
library(allowed_root, ...)` — its structure is test-harness-controlled at
runtime) and InjecAgent's pooled operator pack (`injecagent_pool.py`,
parameterized by which vendored test cases to draw from).

### The structured failure-diagnosis taxonomy

`aginiti/graph/failure_diagnosis.py` — a deliberately conservative
5-category taxonomy: `blocked_by_privilege`, `blocked_by_network_egress`,
`blocked_by_approval_gate` (all three **generalizable** — a confirmed
instance is real structural evidence about *other* operators too) plus
`not_retrieved` and `actively_refused` (deliberately **non-generalizable**
— a bare "didn't retrieve" or "declined this one request" is evidence about
this attempt only, not the boundary). `ClaimEffect.failure_diagnosis`,
`SecurityStateGraph.claim_failure_diagnosis`/`confirmed_failure_diagnoses()`,
and `ObservationAdapter` all thread it through, feeding
`failure_evidence_penalty` (§6). Currently retrofitted onto operators
across DVAA (`mcp_no_auth_check` → `blocked_by_privilege`,
`mcp_fetch_destination_check` → `blocked_by_network_egress`), AnythingLLM
(`anythingllm_rag_injection_trigger` → `not_retrieved`), and the
target-agnostic pack (`system_prompt_extraction` → `actively_refused`);
extending further is a metadata-only addition, not a new claim about any
target's behavior.

### Agentic primitives: approval gates and untrusted tool output

`aginiti/operators/agentic_primitives_definitions.py` — two target-agnostic
primitive *types*, built the same way as `data_exposure.py` (no
target-specific vocabulary): an **approval-gate** primitive (a sensitive
action gated behind a second confirmation step, plus a bypass-attempt
operator that claims prior approval rather than obtaining it) and
**untrusted tool-output content** (a tool's own *return value* — not its
input, and not a RAG-retrieved document — carrying an embedded instruction
the agent then follows). Composed via `ClassPrecondition`, in a second,
independently-authored pack from the discovery-chain demonstration — a
genuine cross-check that the discovery mechanism generalizes. **Not yet
mapped onto a real target's actual endpoints** — validated only in
dry-run form; doing so for a specific live target requires reading that
target's real source and live smoke-testing first, exactly as this
project's own history with DVAA (several previously-planned operators
turned out not to match the target's actual behavior once checked) insists
on.

`ClaimEffect.category` (capability / trust_edge / workflow /
mission_outcome / defender_control) remains the taxonomy every analyst
query and report section filters by, and is **reused across targets**, not
reinvented per target — `CATEGORY_TRUST_EDGE` has been used, unmodified,
for the mock library's Slack/GitHub trust probes, DVAA's A2A
identity-spoofing operators, and DVAA's consensus scenario's voter-identity
trust — evidence the category taxonomy genuinely generalizes across
different protocols (see `docs/EVIDENCE_AND_EVALUATION.md`).

---

## 10. How adapters differ, and how protocols integrate

`BaseAdapter` (`aginiti/adapters/base.py`) is a two-method `Protocol`:

```python
class BaseAdapter(Protocol):
    def send(self, channel: str, prompt: str) -> SendResult: ...
    def ground_truth_mission_achieved(self) -> bool: ...
    # record_suspicious_event() is an OPTIONAL extension, called via
    # getattr(agent, "record_suspicious_event", None) — not every target
    # models a defender-escalation mechanic.
```

Nothing above the adapter boundary — planner, SSG, campaign loop — ever
touches a target directly; everything goes through `send()` and
`ground_truth_mission_achieved()`. This is what makes Aginiti
framework-agnostic: a new target needs a new adapter class plus an operator
library written against its actual behavior, and nothing about the planner
changes. Proven across five genuinely different shapes:

| Adapter | Target | Channel shape | What's structurally new |
|---|---|---|---|
| `DemoAgent` (`target/demo_agent.py`) | Mock Payroll/Slack/GitHub | `"direct"` \| `"slack"` \| `"github_issue"` | Reference/regression only |
| `DVLAAdapter` | damn-vulnerable-llm-agent | `"direct"` only | First real, independently-developed target; LangChain `create_agent`, no indirect channel |
| `DVAAAdapter` | DVAA (19-agent fleet + standalone scenario servers) | `"<protocol>:<target>"` — `api:`, `mcp:`, `a2a:`, `consensus:` | One adapter instance addresses **many** distinct agents across four real protocols, decided per-call by `channel` |
| `McpStdioAdapter` | Official MCP reference servers (subprocess, stdio transport) | `"mcp:<server_name>"` | Async-to-sync bridge: one persistent `asyncio` event loop in a background thread, real `initialize` handshake before any tool call is valid |
| `AnythingLLMAdapter` | AnythingLLM / the hardened gateway | `"direct"` (chat), plus document-plant/upload-link operations | HTTP REST against a real, actively-developed production application; the adapter most exercised by live experiments since exp11 |

`ground_truth_mission_achieved()` is the check that catches a hallucinated
SUCCESS — it scans the adapter's **own raw collected responses** for
target-specific truthful markers, and is explicitly never allowed to read
SSG beliefs. Every adapter implements this independently because every
target's truthful signal is different: DVLA's oracle reads its transaction
DB; DVAA's simulator emits an explicit `VULNERABLE:` marker; the DVAA
consensus scenario checks for `"status": "closed"` AND `"result":
"approved"` as two independent substrings; the AnythingLLM chain operators
cross-check against an *independent listener log* (`infra/
exfil_listener.py`) that receives real outbound requests, not just parses
the target's own claimed response.

**Exception safety.** `ObservationAdapter._send()` wraps every adapter's
`send()` call in a try/except that converts any exception into a
`SendResult(is_synthetic=True)` rather than crashing the campaign — the
single choke point every operator execution passes through, regardless of
which adapter or which of the three execution paths (§4.4) is driving it.
`AnythingLLMAdapter` additionally classifies its own specific failure modes
(timeout, connection error, HTTP error, malformed JSON) via a dedicated
`TargetUnavailable` exception before falling back to this backstop. DVAA
and MCP-stdio are currently protected only by the generic backstop, not
adapter-specific classification the way DVLA and AnythingLLM are — a real,
documented asymmetry, not an oversight (§12).

---

## 11. Why every abstraction exists — the problem that forced it

| Abstraction | Forced by | What breaks without it |
|---|---|---|
| `BaseAdapter` Protocol | Needing DVLA (a second, real target) to plug into the same planner/graph with zero changes to either | Planner/graph code coupled to one target's transport |
| `Fact` as a first-class node | Wanting to answer "what did we literally observe" independent of "what did we conclude" once campaigns got long enough that inference chains got deep | No way to audit a Claim back to raw evidence without re-deriving it |
| `Insight` (4th tier) | DVLA's claim-only reports read as a bag of facts, not reasoning a security engineer could evaluate | No synthesized "what does this imply" layer |
| `InsightCategory.KNOWLEDGE_GAP` + `related_probe_id` | Wanting the graph to be **active** rather than a passive summary | A gap is prose no one acts on |
| `Hypothesis` (mutable, persistent identity) | Knowledge gaps with a `prior_belief` needed something an "accept"/"reject" verdict could actually attach to across separate synthesis rounds | "Model revision after every observation" stays a narrative, not a real update path |
| `gap_priority` / `hypothesis_priority` in the utility function | Insights/Hypotheses existing but never being read by `rank()` | Synthesized understanding never changes what gets probed next |
| `Operator.extractor` (deterministic bypass) | Structured responses (MCP `tools/list`, filesystem boundary checks) don't need an LLM to interpret | Unnecessary LLM calls on evidence that needs no interpretation |
| `graph_edge` + `target_graph.py` (BFS) | Wanting "which trust edge should I exploit next" to be real graph traversal, not flat claim-key matching | `path_progress` degenerates to a proxy with no structural meaning |
| `emergent_impact` | A stepping-stone operator unlocking an unnamed-but-valuable compromise was indistinguishable from a dead end — found by a controlled experiment | Consequence propagation never happens |
| `chain_value` | A multi-step plant operator was structurally incapable of ever outranking a mediocre single-step decoy | Aginiti systematically undervalues real multi-step chains |
| `ClassPrecondition` + semantic hubs | Every chain being a human-hardcoded exact-key sequence meant Aginiti could pivot between chains but never discover one a human hadn't pre-declared | The SSG stays a fixed script with a graph-shaped memory, not a genuine discovery substrate |
| `failure_diagnosis` + `failure_evidence_penalty` | A failed operator confirmed a generic `*_blocked` claim with no reusable signal about *why*, wasting the planner's ability to learn from a block the way it already learns from a success | Repeated attempts against a structurally identical block, no belief transfer |
| Channel-prefix routing (`"<protocol>:<target>"`) | DVAA alone exposing four real protocols across 19 agents on fixed ports | Either one adapter instance per bot, or protocol logic leaking into the operator library |
| Factory-shaped library builders | Some targets' structure is test-harness-controlled at runtime (no fixed "the" filesystem, or a choice of which vendored test cases to draw from) | Can't parameterize the sandbox root / test-case pool without hardcoding |
| `stop_on_mission_success` flag on `run_campaign` | Needing an "understanding mode" that keeps probing past a satisfied mission, without silently changing the frozen RQ1 benchmark's characteristics | Either the benchmark's methodology breaks, or understanding-mode campaigns can't exist |
| `run_understanding_loop` as a **separate** function | Same reason, at the loop level: automatic per-step insight synthesis inside the shared loop would add LLM calls to the frozen protocol | `analysis_plan.md`'s pre-registered cost/timing measurements become invalid |
| `aginiti/target_hardening/` gateway | Wanting a live experiment target that resembles a real enterprise deployment's controls, without needing production access to a real one | Every result is against a soft target, which overstates what Aginiti's findings mean |
| `ObservationAdapter._send()`'s exception backstop | An independent audit found `execute()` had zero exception handling around `agent.send()` — any target-side crash/timeout could kill an entire campaign, and 3 of 4 real adapters relied on this happening to not occur | A flaky target (real production systems are flaky) makes Aginiti itself unreliable, independent of the target's actual security |

**Deliberately not built**, with the reasoning on record:

- **Parallel probe execution** — explicitly not pursued: "performance gain
  today doesn't justify the complexity — optimize against real
  bottlenecks, not hypothetical ones." No target's campaign length has made
  sequential execution an actual bottleneck yet.
- **New graph concepts for the consensus/voting scenario** (participants,
  votes, consensus-state as first-class nodes) — assessed explicitly and
  rejected: the existing Claim/Insight/Hypothesis tiers represent "one
  identity, one or more votes, tallied into an outcome" without strain.
- **A `list_tools()` extension to BaseAdapter** — `queries.observed_tools()`
  is honest that it can only report tools actually *invoked*, not a
  target's full advertised inventory. Flagged as a reasonable next step,
  not bundled into an unrelated change.
- **Real Bayesian confidence** — `ConfidenceBand`'s bounded net-observation
  count is a documented v0 simplification, explicitly flagged as
  replaceable later without a schema change.
- **A unified benchmark harness collapsing the four execution paths
  (§4.4) into one** — real, identified, not yet attempted; each live
  experiment's bespoke scope-shaping is a genuine requirement, not
  laziness, so unifying this needs real design work, not a mechanical
  merge.

---

## 12. Current limitations

- **No single, unified benchmark harness** (§4.4) — four parallel
  execution paths exist (a fourth, `run_full_assessment()`, added
  2026-08-14 specifically because it was worth building even though it
  doesn't unify the other three), each real and tested, but a fix to one
  loop's behavior does not automatically propagate to the others except
  where it lives in `ObservationAdapter` itself.
- **Confidence is a v0 simplification.** `ConfidenceBand` is a bounded,
  weighted net-observation count mapped to LOW/MEDIUM/HIGH — not a real
  Bayesian posterior.
- **Hypothesis resolution is a simple step-update**, not a real
  probabilistic update: ±0.25 per resolving claim against fixed 0.8/0.2
  accept/reject thresholds. The full lifecycle has been proven live exactly
  once (the DVAA consensus run).
- **`observed_tools()` can only report invoked tools**, not a target's full
  advertised inventory.
- **No cross-campaign / cross-target learning.** A category taxonomy has
  generalized across five targets by human design choice, reused
  deliberately each time — there is no mechanism by which the graph itself
  notices "this pattern looks like one I've seen on a different target."
  Explicit, named future direction (`docs/ROADMAP.md` Phase 5).
- **Not every adapter is equally hardened.** AnythingLLM has adapter-
  specific failure classification (`TargetUnavailable`); DVAA and
  MCP-stdio are protected only by `ObservationAdapter._send()`'s generic
  backstop.
- **No `ERROR`/`INCONCLUSIVE` outcome type** on `CampaignResult` — a
  campaign that hits repeated infrastructure failures reports
  `BUDGET_EXHAUSTED`, indistinguishable from a target that genuinely
  defended itself the whole time.
- **A target-side failure permanently exhausts that operator's one
  attempt** — `executed_ids` doesn't distinguish "genuinely failed" from
  "never got a fair chance because the target hiccuped." A real design
  tradeoff, not changed without a deliberate decision.
- **Resolved 2026-08-14, partially**: `aginiti/adaptive/*.py` (now 7
  modules — encoding/many-shot/framing discovery, PAIR refinement,
  Crescendo escalation) is wired into `AginitiPlanner` via
  `aginiti/assessment.py`'s `run_full_assessment()`, but only SEQUENTIALLY
  (discovery phases run to completion, THEN the planner's campaign phase
  runs over the same graph) — the planner still never ranks a live
  adaptive-discovery candidate alongside a static operator WITHIN one
  decision the way it does for two static operators. A real, smaller
  remaining gap, not the original all-or-nothing one.
- **Parallel execution is intentionally absent.** Every campaign and
  understanding loop runs strictly sequentially.
- **The frozen RQ1 benchmark has not been run at the trial counts needed
  for a statistically meaningful result.** See `docs/
  EVIDENCE_AND_EVALUATION.md`'s missing-evidence section — this remains
  true even though exp20 (AnythingLLM) and now exp29 (`hardened_agent`,
  `docs/EXP29_RESULTS.md`) have both produced real, mechanistically-traced
  live evidence of a planning advantage.
- **Resolved 2026-08-14, for `hardened_agent` only**: hand-rolled
  `expNN_*.py` live-experiment scripts previously shared one long-lived
  server process (and therefore conversation memory) across every trial —
  a real, live-confirmed contamination effect that collapsed most of
  exp28's trials to zero real signal. `experiments/_target_lifecycle.py`
  (tested, `psutil`-based stop/start/restart/health-check) closes this for
  `hardened_agent`, wired into exp29. `healthcare_agent` and every prior
  `expNN_*.py` script predating this fix are NOT retrofitted — a real,
  disclosed gap, not silently assumed solved everywhere.
- **`technique_cluster` tagging is not complete across the library.**
  Only 4 clusters across 2 packs (`hardened_authority_claim_probe_
  variants`, `session_isolation_probe_variants`, and `output_filter_
  evasion`'s 2 groups) have been individually verified as genuine near-
  duplicate wrappers and tagged. The remainder of the 115-operator library
  (§ Operator inventory, `docs/AGINITI_OVERVIEW.md` §12) has not been
  audited for the same pattern — real untagged clusters may exist
  elsewhere, understating `technique_cluster_diversification`'s reach.

---

## 13. Future extension points

- **Unifying the three execution paths (§4.4)** into a single benchmark
  harness that can drive any target/library/mission combination — the most
  consequential piece of real technical debt currently identified.
- **A real target-specific validation of the agentic-primitives pack** (§9)
  against DVAA or another live target, closing the one deliberately-scoped
  gap in that work.
- **`BaseAdapter.list_tools()`** — an optional extension, adapter-contract
  level, to close the `observed_tools()` limitation.
- **A real probabilistic confidence model**, replacing the bounded
  net-observation count, without changing `ClaimStatus`/`ConfidenceBand`'s
  external shape.
- **Cross-target pattern recognition** — the graph noticing a recurring
  `CATEGORY_TRUST_EDGE` shape across targets on its own, rather than
  relying on a human choosing to reuse the same category tag each time.
- **Wiring `aginiti/adaptive/*` into `AginitiPlanner`** as first-class
  ranked candidates rather than a separate orchestrator.
- **Adapter-specific failure classification for DVAA and MCP-stdio**,
  matching what AnythingLLM now has, rather than relying solely on the
  generic exception backstop.
