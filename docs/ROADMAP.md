# Aginiti — Intelligence Roadmap

## Update — 2026-08-12: what happened after this roadmap was last touched

This roadmap's Phase 0 status below still reads as "the founding RQ1
question is unresolved, blocked on Groq quota" — that framing is now
superseded, not current. What actually happened, in order: the frozen
DVLA-target RQ1 protocol was never completed as originally scoped, but
the project moved to a new, real, harder target (**AnythingLLM**, a
production-shaped RAG/agent platform) and ran a real sequence of planner
experiments against it — **exp14 through exp19** — culminating in a real,
fixed bug in the planner's own utility function (`chain_value`, closing
the "a plant operator that structurally can't outrank a mediocre single-
step decoy" gap Experiment 7-adjacent work surfaced) and a real,
fair, external comparison against **garak** (NVIDIA's LLM vulnerability
scanner) on a shared hardened target. **`docs/AGINITI_OVERVIEW.md` is now
the authoritative current-state document** — it has the honest, current
answer to "does Aginiti's planning actually help," the full attack
catalog built since Phase 2 below, and the taxonomy/adaptive-discovery
layer none of the phases below mention. Treat everything from "How we got
here" onward in this file as the accurate history through
**2026-08-09**, not the present.

**2026-08-12 addendum:** two more chapters landed the same day —
multi-step attack-path discovery without hardcoded chains, composite
severity-weighted scoring, and a structured failure-diagnosis taxonomy
(`docs/MULTI_STEP_DISCOVERY_AND_SCORING.md`), followed by an independent
engineering-hardening audit that found and fixed 5 real bugs (2
architectural) in the core execution path and added a 10-scenario
deterministic end-to-end test suite plus a live smoke test against the
real hardened AnythingLLM target (`docs/ENGINEERING_HARDENING_PASS.md`).

---

## Executive summary

*Read this section alone and you have the complete trajectory — everything
below is the detailed record behind each line.*

- **What this roadmap tracks:** not features, but reasoning capabilities,
  each labeled **Proven**, **Partially proven**, or **Hypothesized** — code
  existing is never itself evidence.

- **The journey, compressed:** started as one question (does an
  evidence-driven planner beat simpler baselines) on a self-built mock
  target → expanded deliberately to real, independently-built targets
  (DVLA, DVAA, the official MCP filesystem server, DVAA's consensus
  scenario) → hit a real API-quota wall that's still the direct reason the
  founding question is unanswered → made a deliberate governance decision
  (Pivot 6) that this validation track shouldn't block other evidence-driven
  capability work → found and fixed a real planning gap
  (`emergent_impact`) the same day it was discovered. Full account,
  roadblock by roadblock, in "How we got here" below.

- **The governing rule (5 principles, in force since Pivot 6):** a new
  capability only gets built if it solves an *observed* limitation, helps
  across many targets (not one benchmark), improves understanding/planning/
  exploitation (not just infrastructure), gets validated immediately
  against something real, and — if it's a comparative claim — gets an
  experiment, not intuition.
  
- **Phase status, at a glance:**
  - **Phase 0 (adaptive planning substrate)** — mechanism proven built and
    tested; run for real against the mock target 2026-08-07
    (`docs/EVIDENCE_AND_EVALUATION.md` Section 0) and the honest result is
    mixed, not a win: tied Static-enumeration on success rate but at ~2.8x
    the cost, and didn't lead on breadth either. The frozen DVLA-target RQ1
    protocol itself is still unrun at a meaningful trial count.
  - **Phase 1 (behavior understanding)** — complete, proven on all four
    real targets.
  - **Phase 2 (cross-protocol reasoning)** — the taxonomy is proven to
    generalize across three protocols; the graph noticing patterns
    *automatically* (rather than a human tagging them) is not built.
  - **Phase 3 (hypothesis lifecycle)** — the mechanism is proven; the full
    form→test→resolve cycle has been observed live exactly once.
  - **Phase 4 (exploit reasoning)** — real multi-hop path reasoning already
    works (a correction to this document's own earlier text); consequence
    propagation was a genuine gap, found and fixed same-day; success
    probability and true multi-step attack-graph search remain
    Hypothesized, with no forcing target yet.
  - **Phases 5–6 (cross-target learning, autonomous security scientist)**
    — Hypothesized, explicitly not started, and — per the roadmap's own
    discipline — not to be started speculatively.
- **What's next, in order:** finish RQ1 the moment quota allows; analyze
  the result and which utility term is or isn't earning its place; only
  then move toward reducing hand-authored operator/claim knowledge — via a
  dynamic target that forces inference rather than a speculative
  "operator-generation system" built ahead of evidence.
- **For every term used above**, see `docs/ARCHITECTURE.md`'s Glossary. For
  the underlying citations and what's proven vs. only research-motivated,
  see `docs/EVIDENCE_AND_EVALUATION.md`.

---

## New here? Start with this

**What this roadmap is, and isn't.** Not a feature backlog — a map of
reasoning capabilities (Phases 0–6, below) each labeled **Proven**,
**Partially proven**, or **Hypothesized**, where "hypothesized" explicitly
includes things that are fully *implemented* but never demonstrated against
a real target. Code existing is not evidence; a cited live run or controlled
experiment is. Cross-referenced throughout against
`docs/EVIDENCE_AND_EVALUATION.md`, which carries the actual citations this
file only organizes.

**The trajectory.** The project started as a narrow RQ1 question — does an
SSG-driven constrained-utility planner beat Random/Static-enumeration/
Memory-guided baselines — tested against a self-built mock target. It
expanded by deliberately seeking out real, independently-developed targets
rather than deepening the mock one: `damn-vulnerable-llm-agent`, DVAA's
API/MCP/A2A fleet, the official MCP filesystem reference server, DVAA's
consensus/voting scenario. Each one surfaced real bugs only live execution
could have found — an effect-clobbering bug and a judge-polarity bug from
the original benchmark harness, an insight-duplication bug and a
permanently-unresolvable-hypothesis bug from live DVAA runs, a judge
under-reporting a compound effect and a hypothesis-matcher gap in a
precondition chain found and fixed just this session. The Groq per-org
daily token cap has repeatedly blocked benchmark execution — documented in
detail below ("How we got here") because it's the direct, mundane reason
RQ1 — the project's oldest open question — is still unmeasured.

**The operating principle that matters most here.** Every capability that
exists was built because a *specific, already-observed* limitation forced
it, never because it seemed valuable in the abstract — formalized as five
checkable principles (below) after a deliberate pivot decided RQ1 should
validate progress rather than gate it. When that discipline was tested —
a proposal to build browser-automation and exploit-chain machinery ahead of
evidence — it got caught and re-scoped before any code was written. That
discipline, not any single mechanism, is treated as the project's actual
differentiator.

**Where things stand.** Strong, proven, on the *understanding* half:
Fact→Observation→Claim→Insight tiering, cross-protocol category-taxonomy
reuse, deterministic extraction. Weaker on two fronts: **(1)** the planning
advantage RQ1 asks about — tested against the mock target 2026-08-07 via a
second LLM provider built specifically to route around Groq's exhausted
quota, and the honest result doesn't currently show one (tied
Static-enumeration on success rate at ~2.8x the cost; see
`docs/EVIDENCE_AND_EVALUATION.md` Section 0) — the frozen DVLA-target
protocol itself remains unrun at a meaningful trial count; and **(2)** how
much hand-authored knowledge every new target still requires — operators,
claim vocabularies, and `understanding_question`s are still human-written
per target, which is the real ceiling on "point Aginiti at anything with
little or no custom code."

**What's next, in order.** Revisit the early-campaign alpha/beta schedule
against a cost objective specifically — the concrete, evidence-backed
suspect behind the mock-target cost gap, identified, not guessed at. Then
complete the frozen DVLA-target RQ1 protocol at a real trial count, closing
the oldest open question with real numbers instead of a mock-target proxy.
Only then move toward
reducing hand-authored knowledge — and explicitly not by starting with
"build an operator-generation system" (too speculative, no forcing
function yet), but by pointing Aginiti at a dynamic target where nothing
is pre-written, so the system is forced to infer behavior rather than
consume hand-authored operators, and letting whatever actually breaks
there drive the next concrete increment. Full detail in the phases below.
For every term used here, see `docs/ARCHITECTURE.md`'s Glossary; for the
research this design is grounded in (and, just as importantly, exactly
which comparisons are proven versus only architecturally motivated), see
`docs/EVIDENCE_AND_EVALUATION.md`'s "Why this approach" section.

---

_Living document. This is not a feature list — it's organized by what kind of
reasoning capability Aginiti has, is building, or wants next. For every
capability claimed below, exactly one label applies: **Proven**, **Partially
proven**, or **Hypothesized**. Nothing is upgraded to Proven because the
architecture supports it — only because it has been demonstrated on a real
target, with a citation. Cross-reference `docs/EVIDENCE_AND_EVALUATION.md`
for the evidence behind every Proven/Partially proven label here; this file
does not re-derive that evidence, only organizes it by phase._

---

## How we got here

This section exists because the roadmap only makes sense with the roadblocks
and pivots attached — several phases below exist specifically *because*
something upstream broke, was rejected, or forced a redirection. Chronological,
not idealized.

**Stage 0 — Adaptive planning substrate (mock target).** The project started
as a narrower question: does a Security-State-Graph-driven planner beat
Random/Static/Memory-guided baselines at picking the next attack step, against
a self-built mock Payroll/Slack/GitHub agent. Built the SSG core, the
constrained-utility planner, all four policies, and a resumable 4-condition
benchmark harness with persistent per-trial logging. **Two real bugs were
found by the benchmark harness itself, not by manual testing** — an
effect-clobbering bug (same claim key, opposite statuses, silently
overwritten) and a judge-polarity bug (HYPOTHESIZED effects wrongly scored as
negative evidence, which broke recon in a data-dependent fraction of every
campaign). Both are recorded in the top-level `README.md` as a reminder that
scale surfaces bugs single runs don't.

**Roadblock — Groq multi-key rotation didn't multiply budget.** Multiple API
keys were pooled expecting 3x daily token budget; empirically, every rate-limit
error across three "independent" keys referenced the same `org_...` id — Groq
enforces its quota per-organization, not per-key. Keys from the same signup
share one pool. This is the direct cause of every benchmark run in this
project's history being small-trial-count and frequently interrupted
mid-run (see `EVIDENCE_AND_EVALUATION.md` Section 4).

**Roadblock (recurrence, 2026-08-07) — the pool can be collectively drained,
not just one key.** Re-hit live while running the controlled experiments in
`experiments/`: across several fresh attempts at the same script, 429 errors
came back referencing at least two DIFFERENT org ids
(`org_01kzbs43gaes6twbzm55xrkf1w`, `org_01kzbfjbkjemvvvb76hhh1nwm3`), both
sitting within a few hundred tokens of their own 100k/day cap, on the SAME
day, independent of anything this session did (cumulative usage from earlier
work on this long-running project). Two concrete lessons, both acted on
immediately: (1) a naive preflight check that requests only a trivial number
of tokens (an earlier version of `experiments/groq_quota.py` used
`max_tokens=20`) is a false-positive machine -- `_call_with_rotation()` can
always find SOME pooled key with a sliver of headroom for a tiny request,
even when every key's real per-request budget (~500-2000 tokens for an
actual operator/judge call) is already exhausted; fixed by sizing the
preflight probe close to a real call's actual size. (2) key rotation state
(`_current_idx` in `aginiti/llm_client.py`) is a module-level global that
resets to the first key on every fresh process invocation -- so a string of
short-lived `python experiments/exp3_*.py` processes each independently pay
the "try the (possibly exhausted) first key, fail, rotate" cost at the start
of their first real call, rather than a long-running process's rotation
naturally converging on a working key and staying there. Neither of these
is a correctness bug in the pooling mechanism itself (it still does what it
says -- rotate on RateLimitError); they're two operational gaps between
"the mechanism works" and "an experiment script can reliably tell whether
now is a good time to spend a real campaign's budget." `experiments/exp3_*.py`
and `exp4_*.py` were hardened in direct response: a realistic preflight
check before committing to a multi-trial run, and mid-run `RateLimitError`
handling that stops cleanly and preserves every already-completed trial on
disk instead of crashing with a stack trace and (in one case, corrected
immediately after) tempting a premature deletion of already-paid-for data
to "fix" a budget mismatch instead of just documenting the mismatch as a
known limitation.

**Pivot 1 — from "does the planner win" to "graph-first, understanding-first."**
A design conversation established that the SSG — not any single campaign — is
the durable asset, and a campaign is one consumer of it among several
(analyst queries, compliance checks, regression tests, report generation).
This produced: `Fact` as a first-class citizen distinct from belief, graph
persistence (a graph outlives the process that built it), the seven-plus
analyst queries, and the Target Profile as the primary product artifact —
replacing "did the campaign succeed" with "what does Aginiti now understand
about this target" as the organizing question.

**Roadblock — DVLA's original attack technique didn't survive a LangChain
upgrade.** The first real external target, `damn-vulnerable-llm-agent`, had
to be rebuilt on current LangChain (`create_agent`) because the original used
a deprecated agent class. Its headline "ReAct-loop hijacking" technique
(injecting fake Thought/Observation text into a text-parsed scratchpad)
targets an architecture that no longer exists once tool-calling is native and
structured — documented explicitly rather than silently dropped. The
underlying SQL-injection vulnerability was unaffected; the delivery mechanism
had to change.

**Pivot 2 — Insight as a fourth tier, then Security Questions, then
Hypotheses.** Once DVLA was live, claims alone read as a bag of facts, not
reasoning a security engineer could evaluate or push back on. Built
`Insight` (BEHAVIORAL/SECURITY/KNOWLEDGE_GAP, each carrying confidence,
alternative explanations, and specific missing evidence — sharpened
repeatedly against overclaiming), then inverted Security Questions to be
question-keyed rather than operator-keyed ("doctors don't care about blood
tests, they care about whether the patient has diabetes"), then extended
knowledge gaps into testable `Hypothesis` objects — the one deliberately
mutable, persistent-identity object in an otherwise append-only graph.

**Roadblock — a hypothesis that can never resolve is worse than no
hypothesis.** Live DVAA runs surfaced a hypothesis permanently matched to an
operator whose only effect is HYPOTHESIZED, never CONFIRMED — it would sit
stuck at its prior confidence forever, giving a false impression of learning.
Fixed by requiring a CONFIRMED-capable effect before forming a hypothesis at
all: "better to form none than one permanently stuck."

**Pivot 3 — optimization discipline: "every new abstraction must justify its
runtime and complexity."** With the core architecture judged sufficient, the
explicit directive shifted from adding concepts to auditing existing ones.
This surfaced and fixed the insight-duplication bug (≈13 near-duplicate
insights per DVAA campaign, down to 4 distinct) and produced the deterministic
extraction bypass (`Operator.extractor`) — skip the LLM judge entirely when a
response is already structured data. **Explicitly rejected** in the same pass:
parallel probe execution — "performance gain today doesn't justify the
complexity — optimize against real bottlenecks, not hypothetical ones."

**Pivot 4 — away from self-built targets, toward real ecosystems.** A
deliberate redirection: "I don't want Aginiti's progress to become coupled to
targets we designed ourselves." This is the direct cause of every target
integrated since: DVAA's 19-agent fleet (memory/A2A/MCP), the official MCP
filesystem reference server (a genuinely different, stronger transport with a
real `initialize` handshake), and DVAA's standalone consensus/voting scenario.
Each was chosen only after live local verification, never assumed from
documentation.

**Roadblock — RAGBot and DVAA's real-LLM mode, both correctly abandoned.**
RAGBot's declared retrieval-poisoning vulnerability returned `content: null`
against prompts built from DVAA's own trigger list — the vulnerability is
documented but not implemented in the simulator. Building operators against
it would only validate the simulator's gaps, not Aginiti's reasoning — not
pursued. Separately, DVAA's optional real-LLM backend only supports hardcoded
OpenAI/Anthropic endpoints with no Groq support, and the project has no paid
keys for either — set aside rather than requesting new credentials.

**Pivot 5 — "next capability, not next protocol."** An explicit reframing:
protocols are only ways of observing behaviors that outlive protocols. This
retired "which protocol next" as the roadmap's organizing question in favor
of "which class of AI-agent behavior does Aginiti not yet understand" —
identity, memory, trust, tool execution, coordination, and so on. This is the
lens the phases below are organized under.

**Roadblock — Node.js ESM/CommonJS mismatch on the consensus scenario
server.** `voting.js` uses `require()`, but the DVAA repo's root
`package.json` declares `"type": "module"`, so Node refused to run it as
written. Worked around locally with a `.cjs` copy of the file (a scratchpad
fix, not a change to the vendored target) rather than editing the target's
own source.

**Pivot 6 (2026-08-07) — RQ1 validates, it doesn't gate.** A design
conversation about a proposed dynamic-target/browser-adapter capability
surfaced a bigger question: should Phase 4 (exploit reasoning) and beyond
stay hard-gated behind RQ1 actually completing, as originally written below?
Explicit decision: no. RQ1 proves whether the *current* planner beats
today's baselines on today's benchmark — valuable for validation and
publication, but the project's actual objective (understand real AI-agent
security behavior through interaction, keep learning from it, exploit
confirmed weaknesses rigorously) is bigger than winning one benchmark, and
waiting on it would block real capability work for a constraint that's
operational (Groq quota), not architectural. RQ1 still runs, still matters,
still isn't optional — it moves from "gate" to "parallel validation track."
What still governs whether a new capability gets built is not "did RQ1
finish" but the five principles below, applied every time. Also folded in
here: an expanded vision statement (`docs/EVIDENCE_AND_EVALUATION.md`'s
Vision section was updated to add "continuously learning from that
understanding" as an explicit third pillar alongside understanding and
exploiting — not a new goal, a more precise statement of the one that was
already implicit in Phase 5/6's existence).

**Where this leaves us right now:** four real, independently-developed
targets integrated and live-verified (DVLA; DVAA's memory/A2A/MCP surfaces;
the official MCP filesystem server; DVAA's consensus scenario); the full
Fact→Observation→Claim→Insight→Hypothesis pipeline proven end-to-end at least
once each, with one complete hypothesis lifecycle (form→test→ACCEPTED) proven
live exactly once; a category taxonomy (`CATEGORY_TRUST_EDGE` etc.) proven to
generalize across three structurally unrelated protocols without any human
having to invent a new category; and the original adaptive-planning question
this project started with — **does Aginiti's planner actually beat the
baselines** — still not answered at a meaningful sample size, entirely because
of the Groq-quota roadblock above, not because of any architectural doubt.
That gap is the single most consequential piece of unfinished business in the
RQ1 validation track specifically (see Phase 0 below and
`EVIDENCE_AND_EVALUATION.md` Section 4) — but per Pivot 6 above, it is no
longer a precondition for capability work elsewhere in the roadmap.

---

## Principles for adding new capabilities

Replaces the old blanket "gated behind Phase 0" rule everywhere below. Every
capability added from Pivot 6 onward is checked against all five before it
starts, not just the general "which target required this" discipline the
project already had:

1. **Solves a limitation actually observed**, not one imagined in advance —
   a specific claim key that stayed stuck, a matcher that picked the wrong
   operator on a real run, a weight that measurably skewed a real result.
   Not "this seems like it'll matter eventually."
2. **Makes Aginiti better across many targets**, not tuned to one benchmark
   or one target's quirks.
3. **Improves understanding, planning, or exploitation** — not
   infrastructure for its own sake. (Transport/adapter work is real and
   sometimes necessary, but it's an enabler, not this list.)
4. **Validated immediately against an existing real target** (or, where a
   live target isn't the right instrument, a controlled experiment like
   `experiments/` — see `docs/EVIDENCE_AND_EVALUATION.md` Section 0) —
   whenever possible, before moving to the next thing.
5. **Comparative claims need an experiment, not intuition.** If a capability
   is justified by "this should make Aginiti better than X," that claim
   gets a citation in `docs/EVIDENCE_AND_EVALUATION.md` or it doesn't get
   made.

## Phase 0 — Adaptive planning substrate

_Phase status: infrastructure complete; the question it exists to answer is
unresolved._

- Constrained-utility planner (info gain / business impact / path progress /
  gap priority / hypothesis priority), 4-condition benchmark harness,
  resumable trial logging, Fisher's-exact comparison. **Proven** (built,
  unit-tested, exercised in live partial runs).
- **The planner outperforms Random/Static/Memory-guided baselines at a
  statistically meaningful sample size.** **Hypothesized.** This is the
  project's founding question and it has never been answered — every
  benchmark run to date is either pre-bug-fix (unreliable) or was interrupted
  by rate limits before completion. See `EVIDENCE_AND_EVALUATION.md` Section
  4, item 1.

## Phase 1 — Behavior understanding

_Phase status: complete._

- Fact/Observation/Claim tiering, append-only provenance, confidence bands.
  **Proven** — live on all four real targets.
- Insight synthesis (Behavioral/Security/Knowledge-Gap), grounded and
  dedup-guarded. **Proven** — live on DVLA, DVAA, DVAA-consensus; thinner but
  present on the MCP filesystem server.
- Target Profile as the primary product artifact, generated identically from
  a live or reloaded-from-disk graph. **Proven** — four generated profiles on
  disk (`runs/*_target_profile.md`).
- Security Questions (question-keyed, evidence-aggregating). **Proven** —
  rendered in every generated profile.

## Phase 2 — Cross-protocol reasoning

_Phase status: current, and further along than "current" usually implies —
proven three times, not just designed._

- A claim-category taxonomy that generalizes across protocols without being
  reinvented per target. **Proven** — `CATEGORY_TRUST_EDGE` confirmed live
  across mock/Slack, DVAA/A2A, and DVAA/consensus (`EVIDENCE_AND_EVALUATION.md`
  Section 1, Cross-protocol reasoning).
- Deterministic extraction as a general mechanism usable by any structured
  target. **Proven** — live, zero-judge-call on MCP tool discovery, all
  filesystem-server operators, all 3 consensus operators.
- The graph *automatically* noticing a recurring pattern across targets
  without a human choosing the category tag. **Hypothesized.** Not built —
  every reuse of `CATEGORY_TRUST_EDGE` so far was a deliberate human choice
  at operator-authoring time, not an inference the graph made on its own.
  This is the actual boundary of "cross-protocol reasoning" today: the
  *taxonomy* generalizes; the *recognition* doesn't, yet.

## Phase 3 — Hypothesis lifecycle

_Phase status: current._

- Persistent-identity, mutable Hypothesis object; get-or-create by normalized
  statement; wired into `assert_claim` for automatic revision. **Proven** —
  built, 17+ dedicated/integration tests.
- Full lifecycle (knowledge gap → formed hypothesis → tested → resolved).
  **Partially proven** — demonstrated live exactly once (DVAA consensus,
  reached ACCEPTED at confidence 0.80 within a single 3-round campaign).
  Never demonstrated reaching REJECTED live. Accept/reject thresholds are
  uncalibrated v1 constants.
- Hypotheses interacting with each other (resolving one informs another
  related one). **Hypothesized.** Not modeled — each hypothesis resolves
  independently today.

## Phase 4 — Exploit reasoning

_Phase status: underway, not complete — consequence propagation (the item
Experiment 7 found and the same-day fix closed) is the first piece of this
phase built on real evidence rather than guessed at; the rest still waits
on their own forcing functions._

- Multi-hop reasoning toward a KNOWN target. **Proven, and more built than
  this phase's own earlier drafts gave it credit for** — `path_progress`
  runs genuine BFS (`aginiti/graph/target_graph.py`) over the confirmed
  subgraph, which finds shortest paths of any length, not one hop, and
  recomputes every round as the graph grows. Confirmed and unit-tested
  (`test_aginiti_planner.py`), and directly confirmed again by Experiment 7
  before it went looking for a different gap. **Correction to this
  document's earlier text**, which claimed only "one BFS hop" — that
  understated a real, already-working capability.
- **Consequence propagation — the actual, evidence-backed gap. Fixed
  2026-08-07, same day it was found.** Experiment 7
  (`docs/EVIDENCE_AND_EVALUATION.md` Section 0) demonstrated directly: a
  stepping-stone operator that unlocks a genuinely more valuable follow-on
  compromise got IDENTICAL utility to a structurally identical dead end,
  because `business_impact`/`path_progress` are both computed strictly
  against `Mission.success_criteria` — a frozen tuple fixed by a human at
  authoring time, never expanded during a campaign. **Proven** (offline,
  5 new unit tests) — `AginitiPlanner.emergent_impact()` now runs the same
  BFS mechanism against every `CATEGORY_MISSION_OUTCOME`-tagged claim key
  the library itself recognizes, not only the ones named in advance, and
  correctly separates the two cases where the old code couldn't. Honest
  scope, not overclaimed: this only helps once the downstream structure has
  been established somewhere in the graph — a genuine cold start (nothing
  ever confirmed on that chain) still can't be distinguished from a dead
  end, the same "never assume unconfirmed connectivity" character
  `path_progress` itself already has. **Not yet proven:** whether this
  changes real live-campaign behavior — only validated offline so far, a
  live re-run against a real target with a genuine unnamed follow-on
  compromise is the natural next check, not done here.
- Expected success probability per exploit path. **Hypothesized.** No
  probability model exists over exploit paths at all — `RankedCandidate`'s
  `utility` is a planning-time score, not a success-probability estimate.
  Not yet forced by any observed limitation; stays Hypothesized.
- Attack-graph search beyond shortest-distance (e.g. weighing multiple
  candidate paths against each other, not just "does this shorten the
  known-shortest one"). **Hypothesized.** Not yet forced by any observed
  limitation, and likely subsumed by consequence propagation once that
  exists — revisit after, not before.

No longer hard-gated behind Phase 0 completing (Pivot 6) — governed by the
five principles instead. Consequence propagation is the one item here with
real evidence behind it now; the others stay Hypothesized until something
similarly concrete forces them.

## Phase 5 — Continuous learning

_Phase status: not started._

- Graph diffs (what changed between two campaigns against the same target).
  **Hypothesized.** Persistence exists (a graph can be reloaded and extended);
  structured diffing between two graph states does not.
- Cross-target learning (a pattern learned on target A changes how target B
  is approached, automatically). **Hypothesized.** See Phase 2's honest
  boundary above — this is the automatic version of what's currently a
  manual, human-driven taxonomy choice.
- Reusable exploit knowledge (an exploit-chain pattern proven on one target
  becomes a prioritized hypothesis on a structurally similar new target).
  **Hypothesized.** Depends on Phase 4 existing first.

## Phase 6 — Autonomous security scientist

_Phase status: not started; aspirational end-state, not a near-term target._

- Proposes its own experiments (beyond ranking a fixed, human-authored
  operator library). **Hypothesized.**
- Validates hypotheses without a human choosing which operator tests which
  gap. **Hypothesized.** Today's `_match_probe_for_gap` is a human-designed
  heuristic operating over a human-authored library — a step toward this, not
  an instance of it.
- Updates beliefs and discovers genuinely new exploit classes (not
  pre-enumerated in any operator library). **Hypothesized.**

---

## The bigger picture

The founding bet of this project is that an evidence-grounded, persistent
graph — not a stateless prompt-and-score loop — is the right substrate for
understanding AI-agent security behavior, and that rigorous exploitation
should be a *consequence* of that understanding rather than a parallel track.
Four real, independently-developed targets across four structurally different
protocol surfaces have now exercised that substrate without forcing a single
unplanned architectural concept into the graph — every new abstraction in
`docs/ARCHITECTURE.md` Section 9 traces to a specific target that required it,
and every explicitly-considered addition that wasn't required (new graph
concepts for consensus, parallel execution, a semantic gap-matcher) was
turned down with the reasoning on record.

What the project has *not* yet done is close the loop back to the question it
started with: whether any of this actually makes Aginiti a better planner
than doing something dumber and cheaper. That's not a failure of the
architecture — it's an unrun experiment, blocked by a mundane, well-understood
constraint (API quota), not by any open design question. Per Pivot 6, that no
longer blocks everything else — but it stays a parallel, non-optional
validation track, and every capability added while it's outstanding still has
to clear the five principles above on its own, not borrow justification from
"the roadmap says this phase is next." Running RQ1 to completion remains
worth doing for its own sake (it's the difference between an assumed and a
measured planning advantage, and the project's own publication/validation
story depends on it) — it's just no longer the precondition for everything
built above it.
