# Aginiti — Architecture & Codebase Guide

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
  `aginiti/policies/` (planner + 3 baselines sharing one campaign loop),
  `experiments/` (controlled, cited validation of specific claims). Full
  folder-by-folder breakdown in Section 3.

- **How the next probe gets chosen:** a constrained-utility function —
  information gain, business impact against the named mission, real BFS
  path-progress over the confirmed graph, priority from open knowledge gaps
  and hypotheses, and (newest term) *emergent impact*, which values an
  operator that unlocks a recognized-but-unnamed compromise. Risk tier and
  budget are hard constraints, never folded into the same score as
  predicted value. Detail in Section 6.

- **Why the abstractions exist:** every concept in this document — Fact as
  distinct from Claim, the Hypothesis object, deterministic extraction,
  `emergent_impact`, the category taxonomy — was added because a specific
  real target or a specific controlled experiment forced it, not because it
  seemed useful in advance. Section 9 maps every abstraction to the exact
  thing that required it, including things deliberately *not* built and why.

- **Proven on real targets, not just designed:** four independent,
  externally-built systems to date — see "Is this real, or just a design on
  paper?" below and `docs/EVIDENCE_AND_EVALUATION.md` for citations.

- **Known limitations, stated plainly (Section 11):** the confidence model
  is a bounded count, not real Bayesian updating; hypothesis resolution
  uses fixed, uncalibrated thresholds; no exploit-chain search beyond one
  BFS hop; no cross-campaign learning; the frozen benchmark (RQ1) hasn't run
  at a meaningful sample size yet, blocked on API quota, not on design.

- **For definitions of every term used above**, see the Glossary later in
  this document. For what's actually been proven vs. still open, see
  `docs/EVIDENCE_AND_EVALUATION.md`. For where this is headed, see
  `docs/ROADMAP.md`.

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
systematic probing) and pass/fail scored, or manual red-teaming that
requires an operator who already understands the target well enough to
hand-craft an attack chain. Neither produces a durable, structured model of
*how* the target actually behaves.

**What Aginiti is.** An adaptive framework that drives a target through a
`BaseAdapter` (`send(channel, prompt) -> SendResult`,
`ground_truth_mission_achieved() -> bool`) and accumulates everything it
learns into a persistent **Security State Graph (SSG)** rather than a
one-shot transcript. Each probe is an `Operator` — a declared precondition/
effect specification plus the concrete prompt or action, tagged with the
`understanding_question` it answers and an optional deterministic
`extractor` for structured responses. A planner (`AginitiPlanner`) selects
the next operator via a constrained-utility function — information gain,
business impact against the mission's declared success criteria, BFS
path-progress over the confirmed subgraph toward a target, priority from
open knowledge gaps and hypotheses, and (added most recently) *emergent
impact*, which lets an operator that unlocks a compromise the library
recognizes as security-relevant, but that wasn't named in the mission up
front, still get prioritized correctly. Risk tier and budget are hard
constraints on the candidate set, never folded into the same scalar as
predicted impact.

**The evidence model — five tiers, each more interpreted than the last:**
- **Fact** — a raw, uninterpreted data point (a tool call's literal
  arguments, a response's literal text). Append-only, never revised, and
  recorded regardless of whether anything is later inferred from it.

- **Observation** — a judge's (or a deterministic extractor's) verdict
  linking a raw signal to which claim keys it supports or contradicts.

- **Claim** — the versioned belief itself: `HYPOTHESIZED` / `CONFIRMED` /
  `REFUTED`, with a confidence band derived from accumulated observations,
  tagged by category (`trust_edge`, `mission_outcome`, `capability`,
  `workflow`, `defender_control`) so cross-target queries don't need
  protocol-specific code.

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
verified four times over. Targets to date: `damn-vulnerable-llm-agent`
(DVLA, a LangChain `create_agent` pipeline), `damn-vulnerable-ai-agent`
(DVAA, a 19-agent fleet spanning API/MCP/A2A protocols), the official
`@modelcontextprotocol/server-filesystem` reference implementation over
real stdio MCP transport, and DVAA's standalone consensus/voting scenario
server. 
Confirmed findings include an agent trusting a self-reported
identity with zero verification (both in DVAA's A2A layer and, via the
exact same `CATEGORY_TRUST_EDGE` claim category, in the consensus voting
mechanism — evidence the taxonomy genuinely generalizes across unrelated
protocols) and an MCP tool executing with no authentication check. Full
citations for every claim are in `docs/EVIDENCE_AND_EVALUATION.md`; the
capability-by-capability confidence labels and what's next are in
`docs/ROADMAP.md`. This document is the "how it's actually built"
reference — read on for the rest.

## Glossary

Every term used across the three living documents (`ARCHITECTURE.md`,
`EVIDENCE_AND_EVALUATION.md`, `ROADMAP.md`), defined once here so it isn't
maintained three times. Several of these carry forward, sometimes with
light updates, from the original Aginiti Design Document v1.0's own
glossary (Section 26); the rest were added as the system was actually
built. Marked *designed, not built* where the original design named a
concept that hasn't been implemented yet — included for completeness, not
to imply it exists.

**Core system concepts**
- **Security State Graph (SSG)** — the structured, evidence-linked
  belief-state store representing everything Aginiti has learned about a
  target (`aginiti/graph/ssg.py`'s `SecurityStateGraph`). The graph is
  append-only except for `Hypothesis` objects (below); a revised belief
  creates a new version rather than mutating history.
- **Mission** — the current goal, success criteria (a tuple of claim keys),
  budget (in prompts), risk threshold, and constraints for a campaign
  (`aginiti/mission.py`). `success_mode="any"` lets several independent
  compromise types each satisfy the mission; `"all"` requires every
  criterion.
- **Campaign** — one end-to-end execution of the planning loop against a
  target, from mission set to termination (`run_campaign`,
  `aginiti/campaign.py`). A campaign can start from a fresh graph or one
  reloaded from disk, extending prior understanding rather than starting
  over.
- **Understanding loop** — a variant campaign loop (`run_understanding_loop`,
  `aginiti/understanding_loop.py`) that re-synthesizes Insights after every
  single probe and never stops early on mission success, prioritizing
  breadth of understanding over speed to one compromise.
- **BaseAdapter** — the Protocol every target integration implements:
  `send(channel, prompt) -> SendResult` and
  `ground_truth_mission_achieved() -> bool`. The sole boundary between the
  reasoning engine and a target's actual transport (LangChain, HTTP, MCP
  stdio, whatever comes next) — nothing above this line is transport-aware.
- **Ground truth** — an adapter's own, independent check of whether a real
  compromise occurred, read from the target's own raw responses, never
  from what the SSG believes. Exists specifically to catch a planner
  hallucinating success.

**The evidence tiers (Fact → Observation → Claim → Insight → Hypothesis)**
- **Fact** — a directly-observed data point (a tool call's literal
  arguments, a response's literal text), recorded before any
  interpretation and regardless of whether anything is later inferred from
  it. Never revised. (Conceptually the same role as the W3C PROV-O
  provenance ontology's "entity" — recording *what happened*, distinct
  from any belief formed about it.)
- **Observation** — a record (from the LLM judge or a deterministic
  extractor) that a given raw signal supports or contradicts specific
  claim keys. The link between a Fact and a Claim.
- **Claim** — a versioned assertion with a `key` (its stable identity),
  `status` (`HYPOTHESIZED` / `CONFIRMED` / `REFUTED`), and a derived
  `confidence` (`LOW`/`MEDIUM`/`HIGH`, a bounded net-observation count, not
  a real Bayesian posterior — an explicitly documented v0
  simplification). Tagged by **category** — `trust_edge`, `capability`,
  `workflow`, `mission_outcome`, `defender_control` — so analyst queries
  don't need protocol-specific code.
- **Insight** — synthesized higher-order reasoning across multiple claims,
  in one of three categories: **Behavioral** (what the target does),
  **Security** (what that implies for risk), or **Knowledge Gap** (a
  security-relevant question nothing in the graph yet covers, optionally
  linked to the specific unexplored operator that would close it).
- **Hypothesis** — the one deliberately mutable object in the graph: a
  testable prediction with persistent identity (get-or-create by
  normalized statement), status (`OPEN`/`ACCEPTED`/`REJECTED`), and a
  confidence that steps toward resolution as evidence arrives. `Evidence`
  (design doc's own term) is, concretely, the set of Observations backing
  a given Claim or Hypothesis.

**Operators and the planner**
- **Operator** — a planner-agnostic, formalized unit of adversarial action:
  preconditions, predicted effects (`ClaimEffect`s), cost, risk tier, an
  `understanding_question` stating what it teaches independent of whether
  it also lands as an exploit, and an optional deterministic `extractor`
  that bypasses the LLM judge entirely for already-structured evidence.
- **OperatorLibrary** — a collection of Operators for one target, either
  authored directly or (for runtime-parameterized targets like the MCP
  filesystem server) produced by a factory function.
- **Framework Signature** — an optional tag on an Operator identifying
  which agent-orchestration pattern it targets, intended for cross-target
  reuse. Declared in the schema; not yet populated by any current operator
  library — *designed, not exercised yet*.
- **Behavior Pack** — a reference collection of operators, workflows, and
  defense heuristics for a specific orchestration pattern, from the
  original design's vision of reusable, shareable operator bundles.
  *Designed, not built* — today's operator libraries are one-off per
  target, not packaged for reuse.
- **RiskTier** — `LOW` / `MEDIUM` / `HIGH` / `DESTRUCTIVE`, a hard
  constraint on the candidate set (never folded into the same scalar as
  predicted business value). `DESTRUCTIVE` never auto-runs — there is no
  human-approval loop yet, so the current system simply never selects it.
- **AginitiPlanner** — the constrained-utility planner. Ranks eligible
  operators by `alpha * information_gain + beta * (business_impact +
  path_progress + emergent_impact) + gap_priority + hypothesis_priority`,
  with `alpha` decaying and `beta` rising across a campaign (explore early,
  close out late). Each term:
  - **Information gain** — how much is still unresolved about an
    operator's predicted effects.
  - **Business impact** — predicted fraction of the mission's *named*
    unmet success criteria an operator would satisfy.
  - **Path progress** — real BFS shortest-path reasoning
    (`aginiti/graph/target_graph.py`) over the confirmed subgraph: does
    this operator shorten or newly create a path to a named mission
    target?
  - **Emergent impact** — the same BFS mechanism, but against every claim
    key the operator library itself tags `mission_outcome`-category, not
    only the ones a human named in the mission up front. Added to close a
    gap found by Experiment 7 (see `EVIDENCE_AND_EVALUATION.md`): without
    it, an operator that unlocks a genuinely valuable but *unnamed*
    follow-on compromise was indistinguishable from a dead end.
  - **Gap priority** — pull toward operators an open `KNOWLEDGE_GAP`
    insight names as relevant.
  - **Hypothesis priority** — pull toward operators that test an open
    hypothesis, weighted by how *uncertain* that hypothesis currently is
    (peaks at confidence 0.5 — maximally informative to test).
- **Policy** — the interface generalizing `AginitiPlanner` alongside three
  baselines used for comparison: **Random** (uniform among eligible
  operators), **Static-enumeration** (fixed declared order — representative
  of garak/PyRIT-style systematic probing), **Memory-guided** (weighted by
  historical success rate only, no access to the SSG — representative of
  the AutoRedTeamer mechanism).

**Reporting and research framing**
- **Target Profile / Behavioral Security Assessment** — the primary product
  artifact (`aginiti/graph/target_profile.py`): everything currently
  understood about a target, built from the graph alone, rendered
  identically whether the graph came from a live run or one reloaded from
  disk.
- **Security Question** — a question-keyed (not operator-keyed) view over
  the graph: one `understanding_question` from one or more operators, its
  current answer, and confidence — "doctors don't care about blood tests,
  they care about whether the patient has diabetes."
- **RQ1 / RQ1b** — the project's core and secondary research questions
  (`analysis_plan.md`, the frozen benchmark protocol). RQ1: does the SSG-
  driven planner beat Random/Static/Memory-guided baselines at equal or
  lower cost, against a real, independently-developed target? RQ1b
  (secondary, gated on RQ1 being supported): which utility term is doing
  the work, tested via `GreedyInfoGainPlanner`/`GreedyBusinessImpactPlanner`
  (`aginiti/planner/variants.py`), pure parameterizations of the same
  formula with no new mechanism.
- **Understanding-first vs. exploit-first** — framing used in the
  controlled experiments (`experiments/`), not a code construct: does
  prioritizing information gain and open questions (understanding-first,
  `AginitiPlanner`'s default schedule) discover more of a target's behavior
  under a fixed budget than always chasing the named mission target
  directly (exploit-first, `GreedyBusinessImpactPlanner`)?

---

_Living document. Update this file in the same commit/session that changes the
architecture it describes — a stale architecture doc is worse than none._

---

## 1. Philosophy and north star

> **Build the world's best system for understanding the real security behavior
> of AI agents through interaction, and then exploiting them rigorously (and
> aggressively).**

Understanding comes first in that sentence on purpose. The Security State
Graph (SSG) — not any single campaign, exploit, or report — is the durable
asset. A campaign is one *consumer* of the graph, alongside analyst queries,
compliance checks, regression tests, and report generation. Exploitation is a
downstream action the graph's beliefs make possible, not the thing the system
exists to produce.

Concretely, this shows up in the code as:

- `SecurityStateGraph` can be built, saved, reloaded, and queried with **no
  campaign object in scope at all** (`aginiti/graph/queries.py`,
  `aginiti/graph/persistence.py`). A graph outlives the process that built it.
- The primary product artifact is the **Target Profile** — a rendered
  Behavioral Security Assessment (`aginiti/graph/target_profile.py`) — not a
  pass/fail exploit log.
- Every operator declares an `understanding_question` before it declares an
  exploit angle (`aginiti/operators/library.py`). Probes are experiments
  first, attacks second.
- Evidence is layered — **Fact → Observation → Claim → Insight → Hypothesis**
  — so "what literally happened," "what supports a belief," "what we
  currently believe," "what that implies," and "what we're still testing" are
  five different, independently-inspectable things, never collapsed into one.

A second standing rule, adopted mid-project and enforced since: **every new
abstraction must justify its runtime and complexity.** The question asked
before adding any concept is "which currently-integrated target actually
required this?" — never "a future target might need this." Section 9 catalogs
concrete abstractions and the target that forced each one; several explicitly
documented non-additions (concepts considered and rejected) are listed
alongside them.

A third rule: **operators are written from publicly documented technique
classes, never reverse-engineered from a target's exact vulnerable source
line.** Source reading is permitted only to build the ground-truth oracle and
adapter plumbing. This keeps Aginiti's findings generalizable claims about a
behavior class, not a fragile match against one implementation detail.

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
│   │   ├── target_graph.py        BFS shortest-path reasoning over the confirmed subgraph
│   │   ├── insights.py            LLM synthesis: claims -> Behavioral/Security/Knowledge-Gap insights
│   │   ├── target_profile.py      Builds + renders the Behavioral Security Assessment
│   │   ├── persistence.py         SecurityStateGraph <-> JSON on disk
│   │   ├── export.py              SecurityStateGraph -> node-link JSON for visualization
│   │   └── templates/graph_view.html   Standalone interactive graph viewer
│   │
│   ├── operators/                 Operator framework + per-target operator libraries
│   │   ├── library.py             Operator, ClaimEffect, Precondition, OperatorLibrary
│   │   ├── definitions.py         21-operator library for the mock Payroll/Slack/GitHub target
│   │   ├── dvla_definitions.py    3-operator vertical slice for damn-vulnerable-llm-agent
│   │   ├── dvaa_definitions.py    7-operator vertical slice for DVAA (memory/A2A/MCP)
│   │   ├── mcp_filesystem_definitions.py   4-operator factory for the official MCP fs server
│   │   └── dvaa_consensus_definitions.py   3-operator library for DVAA's voting scenario
│   │
│   ├── adapters/                  BaseAdapter implementations for real/external targets
│   │   ├── base.py                 The BaseAdapter Protocol every target implements
│   │   ├── dvla_adapter.py         damn-vulnerable-llm-agent (LangChain create_agent)
│   │   ├── dvaa_adapter.py         DVAA: API / MCP / A2A / consensus channels, 19-agent fleet
│   │   ├── mcp_stdio_adapter.py    Real stdio-transport MCP servers (official reference impls)
│   │   └── vendor/dvla_transaction_db.py   Vendored copy used only to build ground truth
│   │
│   ├── adapter/                   (singular — historical name, kept as-is)
│   │   └── observation_adapter.py  Operator execution -> Fact + Observation + Claim(s)
│   │
│   ├── target/                    The one self-built reference/regression target
│   │   ├── demo_agent.py           Mock agent: Groq-backed tool-calling loop
│   │   └── tools.py                Mock Payroll/GitHub/IT-Helpdesk tools + suspicion state
│   │
│   ├── planner/
│   │   └── aginiti_planner.py      Constrained-utility planner (info gain / impact / path / gaps / hypotheses)
│   │
│   ├── policies/                   Policy = Planner adapted to the shared benchmark interface
│   │   ├── base.py                 Policy Protocol, eligible_operators() (shared substrate)
│   │   ├── aginiti_policy.py       AginitiPlanner wrapped as a Policy
│   │   ├── random_policy.py        Floor baseline
│   │   ├── static_policy.py        Fixed-order enumeration baseline
│   │   └── memory_guided_policy.py Attack-outcome-memory baseline (no SSG access)
│   │
│   ├── campaign.py                 The generic campaign loop (any Policy, any BaseAdapter)
│   ├── understanding_loop.py       Plan -> Execute -> Learn -> Repeat, insight-synthesis-in-the-loop
│   ├── mission.py                  Mission: goal, success criteria, budget, risk threshold
│   ├── scenarios.py                Shared Mission definitions (one per target)
│   ├── benchmark.py                4-condition benchmark harness, resumable
│   ├── report.py                   Loads runs/<id>/*.json -> summary + stats
│   ├── stats.py                    Dependency-free Fisher's exact test
│   ├── pdf_export.py               HTML report -> PDF via headless Chrome/Edge
│   ├── logging_utils.py            JSON-safe serialization, persistent per-trial logging
│   └── llm_client.py               Groq wrapper: chat / chat_json / chat_tools, multi-key rotation
│
├── scripts/                        Runnable entry points (see Section 4)
├── tests/                          252 offline unit tests, no live API/network calls
├── runs/                           Per-run JSON logs, generated reports, saved graphs (gitignored)
├── analysis_plan.md                FROZEN RQ1 benchmark protocol — do not edit after trials begin
├── docs/                           This file, EVIDENCE_AND_EVALUATION.md, ROADMAP.md
└── requirements.txt
```

---

## 3. What every top-level folder is for

| Folder | Role |
|---|---|
| `aginiti/graph/` | The SSG itself: data model, store, reasoning queries, synthesis, I/O. This is the asset everything else serves. |
| `aginiti/operators/` | The **content** layer — what Aginiti can actually try against a target, per target. Operators are data (dataclasses), not code paths; adding a target should not require touching the planner or graph. |
| `aginiti/adapters/` (plural) | The **real-target** integration layer. One class per external system, implementing `BaseAdapter`. This is the only place that knows a target's actual wire protocol. |
| `aginiti/adapter/` (singular) | One file: the bridge between an operator execution and the graph. Deliberately named/organized differently from `adapters/` (historical — kept because a mechanical rename wasn't worth the churn). |
| `aginiti/target/` | The **one** self-built target, kept only as a fast, free, deterministic regression fixture — never scored as evidence for a research question once a real target exists. |
| `aginiti/planner/` | The reasoning that picks the next operator. One class, `AginitiPlanner`, reused by both the benchmark's `AginitiPolicy` and `queries.recommend_next`. |
| `aginiti/policies/` | The abstraction that lets four different "who picks next" strategies drive the identical campaign loop, so a benchmark comparison isolates the policy and nothing else. |
| `scripts/` | Thin, runnable entry points. No logic lives here that isn't in `aginiti/` — a script wires objects together and prints/writes output. |
| `tests/` | Pure-Python, offline. Every LLM call and every network call is mocked; nothing here costs tokens or requires a running server. |
| `runs/` | Generated artifacts: benchmark trial JSON, HTML/PDF reports, saved graphs, rendered Target Profiles. Gitignored — reproducible from source + a live run. |
| `docs/` | This guide, the evidence ledger, and the roadmap — the three living documents referenced from every planning conversation about what to build next. |

---

## 4. End-to-end execution flow

There are two loops in this codebase, deliberately kept separate (see Section
9, "Why `understanding_loop.py` is not inside `campaign.py`"): the **generic
campaign loop** (`run_campaign`) and the **understanding loop**
(`run_understanding_loop`). Both share every layer below the loop itself.

### 4.1 The shared pipeline, one operator execution at a time

```
Mission + OperatorLibrary + SecurityStateGraph + Policy/Planner + BaseAdapter
        │
        ▼
 1. Policy.rank() / Planner.rank()
        — filters library.candidates(ssg) to operators whose preconditions
          currently hold (Operator.preconditions_met)
        — filters further via eligible_operators(): risk tier <= mission
          threshold, cost <= budget remaining, not already executed
        — scores survivors (Aginiti: utility function; baselines: random /
          fixed-order / success-rate-weighted)
        — returns a ranked list; step 2 takes candidate #1
        ▼
 2. Operator.render_prompt(ssg)
        — substitutes {template_var} placeholders with specific facts
          already learned (e.g. a real employee name from an earlier
          confirmed claim), falling back to a generic phrase if none yet
        ▼
 3. BaseAdapter.send(operator.channel, rendered_prompt)
        — delivers the action to the real or mock target
        — returns SendResult(final_text, tool_trace)
        ▼
 4. ObservationAdapter.execute()
        a. ssg.record_fact(...)              <- raw response text, tool calls
                                                  (recorded BEFORE interpretation,
                                                  regardless of what's inferred)
        b. extraction:
             operator.extractor is not None?  -> deterministic extractor(raw_text)
             else                             -> LLM judge (_judge(), chat_json)
        c. ssg.record_observation(...)        <- links raw_signal to the
                                                  claim keys it supports/contradicts
        d. ssg.assert_claim(...) per confirmed effect
                                                <- new Claim version (HYPOTHESIZED /
                                                  CONFIRMED / REFUTED), confidence
                                                  derived from observation counts
                                                <- SSG._update_hypotheses_for_claim()
                                                  fires here: any OPEN Hypothesis
                                                  targeting this claim key updates
                                                  in place
        e. ssg.record_operator_execution(...)  <- operator_stats (one-shot-per-
                                                  operator bookkeeping)
        ▼
 5. (understanding_loop.py only) synthesize_insights(ssg, ...)
        — re-synthesizes BEHAVIORAL / SECURITY / KNOWLEDGE_GAP insights from
          the graph's full current claim set (LLM call)
        — a KNOWLEDGE_GAP with both a prior_belief and a matched,
          CONFIRMED-capable operator becomes a new Hypothesis
          (ssg.form_hypothesis, get-or-create by normalized statement)
        ▼
 6. loop back to step 1 — the NEXT rank() call sees every claim, insight,
    and hypothesis update from this iteration, because gap_priority() and
    hypothesis_priority() read ssg.insights / ssg.hypotheses directly
```

### 4.2 `run_campaign` (`aginiti/campaign.py`)

The loop the frozen RQ1 benchmark measures. Runs steps 1–4 above,
`max_steps` times or until the mission is satisfied (`stop_on_mission_success`,
default `True`) or the library/budget is exhausted. Generic over `Policy` —
the exact same loop mechanics drive all 4 benchmark conditions (Random,
Static, Memory-guided, Aginiti); only which `Policy` is passed in varies.
`ssg` can be a fresh graph or one reloaded from disk, so a campaign can extend
a graph a previous session already built.

### 4.3 `run_understanding_loop` (`aginiti/understanding_loop.py`)

One probe per round, always picked by `AginitiPlanner` (not swappable —
this loop isn't part of the RQ1 ablation), immediately followed by insight
re-synthesis (step 5 above) before the next round's ranking happens. This is
what makes gap-driven planning real: a knowledge gap discovered in round 2
can change which operator gets picked in round 3, because `gap_priority()`
and `hypothesis_priority()` are terms in the same utility function as
information gain and business impact (`aginiti/planner/aginiti_planner.py`).
Stops when no eligible operator has positive utility left, or `max_rounds` is
hit. Never stops early on mission success — the point is to keep learning
past a satisfied mission, not to exit the instant the exploit lands.

### 4.4 Report generation

`build_target_profile()` (`aginiti/graph/target_profile.py`) reads a
`SecurityStateGraph` plus the `OperatorLibrary` and `Mission` that produced
it — nothing else, no campaign object — through the analyst queries in
`aginiti/graph/queries.py`, and assembles a `TargetProfile` dataclass.
`render_markdown()` turns that into the Behavioral Security Assessment: probe
coverage, security questions (question-keyed, not operator-keyed), Behavioral
insights, Security insights, Knowledge gaps, Hypotheses, Capabilities, Trust
relationships, Tool behavior, Observed defenses, Reachable actions,
Unverified claims, Disproven assumptions, Unexplored frontier, and
Recommended next probes. The same function produces the same report whether
the graph came from a run seconds ago or was reloaded from a `.json` file
written days earlier — see `runs/*_target_profile.md` for real generated
examples per target.

The separate benchmark report (`aginiti/report.py` +
`scripts/generate_report.py`) is a different artifact: it compares the 4
policy conditions' trial logs, not a single target's accumulated
understanding — see `analysis_plan.md`.

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
Insights are all append-only — a revised belief creates a new version rather
than mutating the old one, so the graph's history is always reconstructable.
`Hypothesis` is the sole, deliberate exception: without a stable, mutable
identity, "accept" or "reject" has no referent to act on (see Section 9).

---

## 6. How the planner decides the next probe

`AginitiPlanner.rank()` (`aginiti/planner/aginiti_planner.py`) computes, for
every operator whose preconditions currently hold and that hasn't already run:

```
utility(op) = alpha * information_gain(op)
            + beta  * (business_impact(op) + path_progress(op))
            + gap_priority(op)
            + hypothesis_priority(op)
```

- **`information_gain`** — sum of per-effect weights over predicted claim
  keys not yet resolved (still unknown or only hypothesized). A claim already
  confirmed/refuted has no information left to gain.
- **`business_impact`** — fraction of currently-unmet mission
  success-criteria this operator's success effects would satisfy.
- **`path_progress`** — real BFS graph reasoning, not flat key-matching:
  builds the currently-CONFIRMED subgraph (`target_graph.py`), asks whether
  hypothetically adding this operator's `graph_edge` shortens or newly
  creates a path to any mission-target node.
- **`gap_priority`** — sums importance-weighted contributions from every
  open `KNOWLEDGE_GAP` insight whose `related_probe_id` names this operator.
  This is the literal mechanism by which synthesized understanding reshapes
  planning: without it, an Insight is read-only commentary the planner never
  sees.
- **`hypothesis_priority`** — sums `Hypothesis.uncertainty`-weighted
  contributions from every OPEN hypothesis that lists this operator as one of
  its `experiments`. `uncertainty` peaks at confidence 0.5 (maximally
  informative to test) and is 0 once resolved, so a near-settled hypothesis
  naturally stops competing for the planner's attention.
- `alpha`/`beta` follow a fixed schedule: `alpha` decays and `beta` rises as
  `prompts_used / budget` grows — early in a campaign, learn; late in a
  campaign, close out mission-relevant paths.

Risk tier and budget are **hard constraints** on the candidate set
(`eligible_operators` in `aginiti/policies/base.py`), not penalty terms
folded into the same scalar as business impact — a large predicted impact
must never numerically outweigh a disallowed risk tier. An operator with
`utility <= 0` is dropped entirely: a rational planner has no reason to run
it. The three baseline policies (Random, Static, Memory-guided) share the
exact same `eligible_operators()` gate, so a benchmark comparison isolates
*ranking strategy* and nothing else.

---

## 7. How operators are structured

An `Operator` (`aginiti/operators/library.py`) is a frozen dataclass — data,
not a code path:

| Field | Purpose |
|---|---|
| `preconditions` | Claim-key/status pairs that must hold before this operator is even eligible |
| `effects_success` / `effects_failure` | *Predicted* claim-key deltas (`ClaimEffect`s) — the Observation Adapter reconciles these against what the target actually did and only applies what the evidence supports |
| `channel` | Which adapter-specific delivery surface to use (`"direct"`, `"slack"`, `"api:legacybot"`, `"mcp:filesystem"`, `"consensus:voting"`, ...) |
| `understanding_question` | What this probe teaches, independent of whether it also lands as an exploit |
| `extractor` | Optional deterministic bypass for the LLM judge (see Section 8) |
| `graph_edge` | `(from_node, to_node)` — what confirming this operator's success means structurally, feeding `target_graph.py`'s path reasoning |
| `template_vars` | `{prompt_placeholder: claim_key}` — lets a prompt reference a fact actually learned earlier, instead of generic boilerplate |
| `risk_tier`, `cost_prompts` | Hard constraints the planner enforces |

`ClaimEffect.category` (capability / trust_edge / workflow / mission_outcome
/ defender_control) is the taxonomy every analyst query and report section
filters by. It is **reused across targets**, not reinvented per target — the
same `CATEGORY_TRUST_EDGE` tag has now been used for the mock library's
Slack/GitHub trust probes, DVAA's A2A identity-spoofing operators, and the
DVAA consensus scenario's voter-identity trust — concrete evidence that the
category taxonomy generalizes across genuinely different protocols (see
`docs/EVIDENCE_AND_EVALUATION.md`).

An `OperatorLibrary` is just a dict-backed collection with `.candidates(ssg)`
(precondition filtering) and `.get(id)`. Most targets export a no-argument
`build_X_library()`. The MCP filesystem target is the one exception: its
structure is test-harness-controlled (there's no fixed "the" filesystem to
probe), so it exports `build_filesystem_mcp_library(allowed_root,
inside_file_path, ...)` — a factory parameterized by runtime paths. That
shape difference was forced by the target, not chosen speculatively.

---

## 8. How adapters differ, and how protocols integrate

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
changes. Proven four times over, each with a genuinely different shape:

| Adapter | Target | Channel shape | What's structurally new |
|---|---|---|---|
| `DemoAgent` (`target/demo_agent.py`) | Mock Payroll/Slack/GitHub | `"direct"` \| `"slack"` \| `"github_issue"` | Reference/regression only |
| `DVLAAdapter` | damn-vulnerable-llm-agent | `"direct"` only | First real, independently-developed target; LangChain `create_agent`, no indirect channel — sophistication comes entirely from crafted prompt content |
| `DVAAAdapter` | DVAA (19-agent fleet + standalone scenario servers) | `"<protocol>:<target>"` — `api:`, `mcp:`, `a2a:`, `consensus:` | One adapter instance addresses **many** distinct agents across three real protocols, decided per-call by `channel`, not by construction |
| `McpStdioAdapter` | Official MCP reference servers (subprocess, stdio transport) | `"mcp:<server_name>"` | Async-to-sync bridge: one persistent `asyncio` event loop in a background thread for the adapter's lifetime, real `initialize` handshake before any tool call is valid — a genuinely different transport than DVAA's simplified HTTP JSON-RPC-without-handshake MCP servers |

`ground_truth_mission_achieved()` is the check the benchmark harness uses to
catch a hallucinated SUCCESS — it scans the adapter's **own raw collected
responses** for target-specific truthful markers, and is explicitly never
allowed to read SSG beliefs. Every adapter implements this independently
because every target's truthful signal is different: DVLA's oracle reads its
transaction DB; DVAA's simulator emits an explicit `VULNERABLE:` marker;
the DVAA consensus scenario (a real, non-simulated server) has no such
marker and is instead checked by looking for `"status": "closed"` AND
`"result": "approved"` as two independent substrings in the raw JSON — a
bug caught and fixed before it could silently under-report a real compromise
(see `docs/EVIDENCE_AND_EVALUATION.md`, Adaptive planning / Ground-truth
validation section).

---

## 9. Why every abstraction exists — the problem that forced it

| Abstraction | Forced by | What breaks without it |
|---|---|---|
| `BaseAdapter` Protocol | Needing DVLA (a second, real target) to plug into the same planner/graph with zero changes to either | Planner/graph code coupled to one target's transport |
| `Fact` as a first-class node | Wanting to answer "what did we literally observe" independent of "what did we conclude" once campaigns got long enough that inference chains got deep | No way to audit a Claim back to raw evidence without re-deriving it |
| `Insight` (4th tier) | DVLA's claim-only reports read as a bag of facts, not reasoning a security engineer could evaluate | No synthesized "what does this imply" layer; every report is just claims restated |
| `InsightCategory.KNOWLEDGE_GAP` + `related_probe_id` | Wanting the graph to be **active** (drive what happens next) rather than a passive summary | A gap is prose no one acts on; the planner has no way to know a gap exists |
| `Hypothesis` (mutable, persistent identity) | Knowledge gaps with a `prior_belief` needed something an "accept"/"reject" verdict could actually attach to across separate synthesis rounds — Insight's append-only log mints a new entry every round with nothing to update | "Model revision after every observation" stays a narrative, not a real update path; a resolved gap looks identical to an unresolved one |
| `gap_priority` / `hypothesis_priority` in the planner's utility | Insights/Hypotheses existing but never being read by `rank()` — they'd be commentary the planner ignores | Synthesized understanding never changes what gets probed next |
| `Operator.extractor` (deterministic bypass) | DVAA's MCP `tools/list` responses and the filesystem server's boundary-check responses are **already structured data** — running an LLM judge over them is slower, costlier, and strictly less reliable than a pure function | Unnecessary LLM calls on evidence that needs no interpretation |
| `understanding_question` on Operator | Wanting "operators are experiments first, exploits second" to be literal metadata a report can render, not only a design narrative | Security Questions section has nothing to key off of |
| `graph_edge` + `target_graph.py` (BFS) | Wanting the planner to answer "which trust edge should I exploit next" as real graph traversal, not flat claim-key matching | `path_progress` degenerates to a proxy with no structural meaning |
| `success_mode="any"` on Mission | A single linear AND-chain mission gives every policy the same one path — no real selection decision to benchmark | RQ1's comparison becomes trivial; nothing differentiates the four conditions |
| Channel-prefix routing (`"<protocol>:<target>"`) | DVAA alone exposing three real protocols across 19 agents on fixed ports — a single adapter instance has to address all of them | Either one adapter instance per bot (19x the objects) or protocol logic leaking into the operator library |
| MCP filesystem's factory-shaped library builder | That target's structure is test-harness-controlled at runtime (no fixed "the" filesystem) — unlike every other target's no-argument `build_X_library()` | Can't parameterize the sandbox root without hardcoding a path |
| `stop_on_mission_success` flag on `run_campaign` | Needing an "understanding mode" that keeps probing past a satisfied mission, without silently changing the frozen RQ1 benchmark's token-budget/timing characteristics | Either the benchmark's methodology breaks, or understanding-mode campaigns can't exist |
| `run_understanding_loop` as a **separate** function from `run_campaign` | Same reason as above, at the loop level: automatic per-step insight synthesis inside the shared loop would add LLM calls to the frozen protocol | `analysis_plan.md`'s pre-registered cost/timing measurements become invalid |

**Deliberately not built**, with the reasoning on record:

- **Parallel probe execution** — a real engineering option, explicitly not
  pursued: "performance gain today doesn't justify the complexity — optimize
  against real bottlenecks, not hypothetical ones." No target's campaign
  length has made sequential execution an actual bottleneck yet.
- **New graph concepts for the consensus/voting scenario** (participants,
  votes, consensus-state, influence-paths as first-class nodes) — assessed
  explicitly before building `dvaa_consensus_definitions.py` and rejected:
  the existing Claim/Insight/Hypothesis tiers represent "one identity, one or
  more votes, tallied into an outcome" without strain. Zero new graph
  primitives were added for the fourth real target in a row.
- **A `list_tools()` extension to BaseAdapter** — `queries.observed_tools()`
  is honest that it can only report tools actually *invoked*, not a target's
  full advertised inventory (DVLA's tools live inside a LangChain agent
  object with no declared list). Flagged as a reasonable next step, not
  bundled into an unrelated change.
- **Real Bayesian confidence** — `ConfidenceBand`'s bounded net-observation
  count is a documented v0 simplification, explicitly flagged as replaceable
  later without a schema change, not silently presented as more rigorous
  than it is.

---

## 10. Deterministic extraction vs. LLM reasoning

Every operator execution needs to turn a raw target response into confirmed
claim-key deltas. Two paths exist, chosen per-operator via
`Operator.extractor`:

```
        raw_signal
            │
            ▼
  operator.extractor is not None?
       │                    │
      yes                   no
       │                    │
       ▼                    ▼
  pure function          LLM judge (chat_json)
  extractor(raw_signal)  _judge(operator, raw_signal)
  -> ["<key>::<status>"] -> {"confirmed_effect_ids": [...],
       no LLM call            "details": {...}, "reasoning": ...}
       no cost                one Groq call, tokens + latency + judge error surface
```

The deterministic path is used exactly where the response is **already
structured data that needs no interpretation** — an MCP `tools/list`
JSON-RPC result, a filesystem server's `Access denied` vs. success response,
a consensus server's vote-tally JSON. In all of these cases, writing a parser
is strictly better than asking a model to read JSON and guess: cheaper,
faster, and — critically — not subject to judge misreads. The stated
direction from early in the project ("the LLM should become the exception,
not the default") is currently true for every operator against DVAA's MCP
surfaces, the official filesystem server, and the entire consensus scenario;
it is **not** yet true for the mock library, DVLA, or DVAA's memory/A2A
operators, where the target's response is genuinely free-form natural
language a judge has to interpret. Extending deterministic extraction
further requires the underlying response to actually be structured — it
cannot be forced onto free-text targets without losing information the judge
path currently captures (extracted specific facts like a name or dollar
figure, used to make follow-up prompts contextual via `template_vars`).

---

## 11. Current limitations

- **Confidence is a v0 simplification.** `ConfidenceBand` is a bounded,
  weighted net-observation count mapped to LOW/MEDIUM/HIGH — not a real
  Bayesian posterior. Documented as replaceable without a schema change, not
  yet replaced.
- **Hypothesis resolution is a simple step-update**, not a real probabilistic
  update: ±0.25 per resolving claim against fixed 0.8/0.2 accept/reject
  thresholds. The full lifecycle (form → test → resolve) has been proven live
  exactly once (the DVAA consensus run) — see
  `docs/EVIDENCE_AND_EVALUATION.md`.
- ~~`_form_hypothesis_if_testable` only looks at ONE matched operator~~ —
  **fixed 2026-08-07.** `_find_resolving_chain()` now does a bounded BFS
  through the full library's precondition graph starting at the matched
  operator, so a plant-then-recall pair (the exact real case this was found
  against, live on DVAA) correctly forms a hypothesis targeting "recall"'s
  effect with both operators recorded as `experiments`. See
  `docs/EVIDENCE_AND_EVALUATION.md`'s Hypotheses section for the test
  coverage this shipped with.
- **`observed_tools()` can only report invoked tools**, not a target's full
  advertised inventory — `BaseAdapter` has no `list_tools()` method yet.
- **No recovery-after-failure or branch-efficiency metrics** in the benchmark
  (tracked, not yet built — see `docs/ROADMAP.md`).
- **No cross-campaign / cross-target learning.** A category taxonomy
  (`CATEGORY_TRUST_EDGE` etc.) has now generalized across four targets by
  human design choice, reused deliberately each time — but there is no
  mechanism by which the graph itself notices "this trust pattern looks like
  one I've seen on a different target" automatically. That's an explicit,
  named future direction (`docs/ROADMAP.md` Phase 5), not a current
  capability.
- **The exploit planner does not reason about exploit chains, success
  probability, or attack-graph search** beyond the current single-hop
  `path_progress` BFS term. Multi-step consequence propagation is Phase 4
  work, not started.
- **Parallel execution is intentionally absent.** Every campaign and
  understanding loop runs strictly sequentially.
- **The frozen RQ1 benchmark has not been run at the trial counts needed for
  a statistically meaningful result.** Every benchmark run to date used
  single-digit trial counts per condition, constrained by free-tier Groq
  token budgets — see `docs/EVIDENCE_AND_EVALUATION.md`'s missing-evidence
  section.

---

## 12. Future extension points

- **A fifth real target chosen for a genuinely new behavioral dimension**
  (not protocol) not yet covered — candidates per the roadmap's own
  discipline: planning/delegation depth (a real LangGraph multi-agent
  system), retrieval/RAG poisoning against a target that actually implements
  it (DVAA's RAGBot was investigated and rejected — the vulnerability is
  declared but not implemented in the simulator).
- **`BaseAdapter.list_tools()`** — an optional extension, adapter-contract
  level, to close the `observed_tools()` limitation above.
- ~~Hypothesis identity resolution improvements~~ — **done**, see Section 11.
- **A real probabilistic confidence model**, replacing the bounded
  net-observation count, without changing `ClaimStatus`/`ConfidenceBand`'s
  external shape.
- **Cross-target pattern recognition** — the graph noticing a recurring
  `CATEGORY_TRUST_EDGE` shape across targets on its own, rather than relying
  on a human choosing to reuse the same category tag each time.
- **Exploit-chain reasoning** — extending `path_progress` from a single-hop
  BFS term into genuine multi-step attack-graph search with consequence
  propagation (Phase 4 in `docs/ROADMAP.md`).
- ~~Greedy-Information-Gain / Greedy-Business-Impact planner variants~~ —
  **implemented** (`aginiti/planner/variants.py`:
  `GreedyInfoGainPlanner`, `GreedyBusinessImpactPlanner`, plus a third,
  `BFSOnlyPlanner`, that `experiments/exp3_understanding_first_vs_baselines.py`
  needed and RQ1b didn't originally name) **and run live 2026-08-07**
  (`docs/EVIDENCE_AND_EVALUATION.md` Section 0): `GreedyBusinessImpactPlanner`
  and `BFSOnlyPlanner` both failed to take a single step from a cold start
  in every trial — a real, reproducible finding (no operator has positive
  business_impact or path_progress before anything is confirmed), not a bug
  — direct evidence for why `information_gain` needs to stay in the utility
  function even in a pure exploit-first or pure path-following variant.
