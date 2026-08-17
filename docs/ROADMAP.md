# Aginiti — Intelligence Roadmap

_Last rewritten 2026-08-13. This is not a feature list — it's organized by
what kind of reasoning capability Aginiti has, is building, or wants next.
For every capability claimed below, exactly one label applies: **Proven**,
**Partially proven**, or **Hypothesized**. Nothing is upgraded to Proven
because the architecture supports it — only because it has been
demonstrated on a real target, with a citation. Cross-reference `docs/
EVIDENCE_AND_EVALUATION.md` for the evidence behind every label here; this
file organizes it by phase, it doesn't re-derive it._

---

## Executive summary

*Read this section alone and you have the complete trajectory — everything
below is the detailed record behind each line.*

- **What this roadmap tracks:** not features, but reasoning capabilities,
  each labeled Proven, Partially proven, or Hypothesized — code existing is
  never itself evidence.

- **The journey, compressed:** started as one question (does an
  evidence-driven planner beat simpler baselines) on a self-built mock
  target → expanded deliberately to real, independently-built targets
  (DVLA, DVAA, the official MCP filesystem server, DVAA's consensus
  scenario) → hit a real API-quota wall that's still the direct reason the
  founding question's frozen protocol is unanswered → made a deliberate
  governance decision (Pivot 6) that validation shouldn't gate capability
  work → integrated AnythingLLM, a real production-shaped RAG/agent
  platform, as a new primary live target → built a self-hosted, hardened
  gateway to test against something production-realistic rather than a
  soft target → ran a real, fair external comparison against garak → found
  and fixed two separate real planning gaps (`emergent_impact`,
  `chain_value`) against live evidence → ran a 150-trial live benchmark
  (exp20) that produced the strongest evidence yet of a real planning
  advantage → built genuine multi-step attack-path *discovery*
  (`ClassPrecondition`), not just execution of pre-wired chains → ran an
  independent, from-scratch engineering audit that treated "500+ tests
  pass" as insufficient proof of a sound architecture and found 5 real
  bugs anyway → vendored two more real RAG targets (`hardened_agent`/
  `healthcare_agent`, real RBAC + real document corpora) → built
  `run_full_assessment()`, the fourth execution path that actually wires
  the adaptive-discovery engines (encoding/many-shot/framing/Crescendo)
  into a normal `AginitiPlanner` campaign over one shared graph, closing a
  standing limitation rather than leaving it as a documented gap forever →
  a live postmortem of that run found and fixed two real judge/oracle
  bugs (an LLM-judge false positive, a fuzzy-oracle boilerplate
  miscalibration) plus a THIRD, more consequential one (`_corroborated()`'s
  own ground-truth check had a blind spot for exactly the goal every
  discovery phase actually pursues) → a source-level read of the target's
  real RBAC implementation explained WHY its boundary had never been
  crossed (correct, retrieval-time pre-filtering — a real property of the
  target, not an Aginiti gap) → implemented the Interrogation Attack
  (membership inference against a RAG corpus) → its first live run showed
  the mechanism itself works, then its SECOND live run (appended after a
  long prior session) showed the signal completely collapsing under real
  conversation-state contamination → root-caused, fixed (fresh-server,
  MI-first ordering), and re-verified clean and consistent across all 3
  personas (average score gap 1.06) → closing a capability gap this
  project's own dataset-prep script had been naming since before the
  technique existed here. Full arc: `docs/EXP26_RESULTS.md`. → ran exp28,
  the first live instance of RQ1's own 4-condition methodology (Random/
  Static/Aginiti) against a real target, and read the user's own postmortem
  of it seriously rather than defensively: Aginiti's live sequence spent
  its entire budget on two attack families, a live memory-contamination
  effect (documented as a known gotcha, not actually mitigated) collapsed
  10 of 12 trials to zero signal, and the family-diversification mechanism
  itself was suspected of running backwards → root-caused two SEPARATE,
  real gaps rather than one — a missing PROACTIVE bonus for genuinely
  untried families (families were only ever pushed toward reactively,
  after a sibling already looked dead) and a missing WITHIN-family signal
  (`technique_cluster_diversification_term`, since several of hardened_
  agent's own `direct_prompt_attack` operators are near-duplicate wrappers
  of one hypothesis, not independent techniques) — fixed both, each
  isolated and offline-proven separately (exp30, exp31) before touching
  anything live, then built `experiments/_target_lifecycle.py` to close
  the memory-contamination gap for real (fresh server process, not just a
  documented warning) → re-ran the corrected comparison (exp29, 9 trials,
  a genuine 3-persona sweep rather than a repeated seed) and it held live:
  Aginiti 3/3 ground-truth successes against Random's 2/3 and Static's
  1/3, the only policy to reach all 6 attack families in one campaign →
  a follow-up evidence-only audit (excluding every LLM-judge-confirmed
  claim, keeping only the independent verbatim/fuzzy oracle) found 10
  distinct real findings across the 9 trials, 2 of them genuine RBAC/
  authorization crossings (the `ops` persona receiving non-`ops_visible`
  content via its own aggregation probes), the rest RAG/generation-
  guardrail over-disclosure — and confirmed the 5 dedicated authority-
  claim social-engineering probes never once crossed the boundary they
  were built to test. Full arc: `docs/EXP29_RESULTS.md`.

- **The governing rule (5 principles, in force since Pivot 6):** a new
  capability only gets built if it solves an *observed* limitation, helps
  across many targets (not one benchmark), improves understanding/planning/
  exploitation (not just infrastructure), gets validated immediately
  against something real, and — if it's a comparative claim — gets an
  experiment, not intuition.

- **Phase status, at a glance:**
  - **Phase 0 (adaptive planning substrate)** — mechanism proven built and
    tested. The evidence picture keeps improving with each real run, not
    just accumulating: against the mock target with the earlier planner
    (2026-08-07), Aginiti tied Static-enumeration on success rate at ~2.8x
    the cost — not a win. Against a real, hardened, production-shaped
    target with an earlier planner version (exp20, 2026-08-12), Aginiti
    produced a real, mechanistically-traced planning advantage that four
    other strategies — including a real Bayesian bandit — never
    reproduced. exp29 (2026-08-14) is the first LIVE run of RQ1's own
    4-condition methodology (Random/Static/Aginiti) against `hardened_
    agent`, at equal budget, with independent per-trial state (fresh
    server restart) and genuine replication (a 3-persona sweep, not a
    repeated seed): Aginiti won ground-truth success on all 3 personas
    (Random 2/3, Static 1/3) and was the only policy to reach all 6
    attack families in one campaign — see `docs/EXP29_RESULTS.md` for the
    full, evidence-only findings audit behind that number. Still honestly
    underpowered (N=3), and the frozen DVLA-target RQ1 protocol itself
    remains unrun at a meaningful trial count — that piece of unfinished
    business is unchanged by exp29.
  - **Phase 1 (behavior understanding)** — complete, proven on all five
    real targets.
  - **Phase 2 (cross-protocol reasoning)** — the taxonomy is proven to
    generalize across three protocols; the graph noticing patterns
    *automatically* (rather than a human tagging them) is not built.
  - **Phase 3 (hypothesis lifecycle)** — the mechanism is proven; the full
    form→test→resolve cycle has been observed live exactly once.
  - **Phase 4 (exploit reasoning)** — the most active phase in the project
    right now. Multi-hop path reasoning toward a *known* target works;
    consequence propagation toward an *unnamed* target (`emergent_impact`)
    and value-informed chain credit (`chain_value`) are both found, fixed,
    and evidence-backed; genuine multi-step *discovery* (`ClassPrecondition`)
    — not just executing a chain a human pre-wired — now exists and is
    proven offline. Two family/technique-level exploration mechanisms
    landed this chapter, each isolated and independently offline-proven
    before being confirmed live in exp29: `family_diversification_term`'s
    `PROACTIVE_COVERAGE_BONUS` (a genuinely untried attack FAMILY earns a
    small bonus unconditionally, not only once a sibling family already
    looks dead) and `technique_cluster_diversification_term` (an author-
    declared `technique_cluster` of near-duplicate operator WRAPPERS gets
    an escalating, deliberately NOT success-immune penalty for repeated
    sampling — the one place this term's shape differs on purpose from
    family-level saturation). Success-probability modeling and full
    attack-graph search (weighing multiple candidate paths, not just
    shortening a known one) remain Hypothesized.
  - **Phases 5–6 (cross-target learning, autonomous security scientist)** —
    Hypothesized, explicitly not started, and — per the roadmap's own
    discipline — not to be started speculatively.
- **What's next, in order:** get exp29's N past 3 per condition — the
  real, disclosed ceiling right now is that `static`/`aginiti` are fully
  deterministic given identical starting state, so persona is their only
  genuine independent-trial axis, and 3 personas is the whole roster this
  target has; close the WITHIN-family diversity gap `technique_cluster`
  only partially covers — several packs (all of `encoding_variants.py`'s
  13 base pipelines, `redaction_format_evasion.py`'s 5 PII-type variants)
  were deliberately left untagged after inspection showed they're
  genuinely distinct techniques, not near-duplicate wrappers, but that
  audit hasn't been run over the FULL library yet; run the frozen DVLA
  RQ1 protocol the moment quota allows; get a larger N specifically on
  exp20's chain-required mission, since the current pairwise result
  (p=0.224) is real but underpowered; exercise `ClassPrecondition` against
  a live target with genuinely undeclared topology, not a demonstration
  pack; validate the agentic-primitives pack against a real target (DVAA,
  most likely); unify the four parallel execution paths an independent
  audit identified (one closed 2026-08-14 via `run_full_assessment()`,
  three remain) before adding more capability on top of them; extend
  `membership_inference.py` toward the paper's own n=30-probe default and
  real ROC-based threshold calibration now that the mechanism itself is
  live-verified working.
- **For every term used above**, see `docs/ARCHITECTURE.md`'s Glossary. For
  the underlying citations, see `docs/EVIDENCE_AND_EVALUATION.md`.

---

## How we got here

This section exists because the roadmap only makes sense with the
roadblocks and pivots attached — several phases below exist specifically
*because* something upstream broke, was rejected, or forced a
redirection. Chronological, not idealized.

**Stage 0 — Adaptive planning substrate (mock target).** The project
started as a narrower question: does a Security-State-Graph-driven planner
beat Random/Static/Memory-guided baselines at picking the next attack step,
against a self-built mock Payroll/Slack/GitHub agent. Built the SSG core,
the constrained-utility planner, all baseline policies, and a resumable
4-condition benchmark harness with persistent per-trial logging. Two real
bugs were found by the benchmark harness itself, not by manual testing —
an effect-clobbering bug and a judge-polarity bug (HYPOTHESIZED effects
wrongly scored as negative evidence).

**Roadblock — Groq multi-key rotation didn't multiply budget, and the pool
can be collectively drained, not just one key.** Multiple API keys were
pooled expecting 3x daily token budget; empirically, every rate-limit error
across "independent" keys referenced the same `org_...` id — Groq enforces
quota per-organization, not per-key. This is the direct cause of every
benchmark run in this project's history being small-trial-count and
frequently interrupted. Re-hit live on 2026-08-07 across two different
org ids in the same pool, on the same day, independent of anything that
session did. Fixed operationally (a realistic preflight probe, mid-run
graceful stop-and-resume) — not a correctness bug in the pooling
mechanism, an operational gap between "the mechanism works" and "a script
can reliably tell whether now is a good time to spend budget."

**Pivot 1 — from "does the planner win" to "graph-first, understanding-
first."** The SSG — not any single campaign — is the durable asset, and a
campaign is one consumer of it among several. Produced: `Fact` as a
first-class citizen, graph persistence, the analyst queries, and the
Target Profile as the primary product artifact.

**Roadblock — DVLA's original attack technique didn't survive a LangChain
upgrade.** The first real external target had to be rebuilt on current
LangChain (`create_agent`) because the original used a deprecated agent
class; its headline technique targeted an architecture that no longer
exists once tool-calling is native and structured. Documented explicitly
rather than silently dropped.

**Pivot 2 — Insight as a fourth tier, then Security Questions, then
Hypotheses.** Claims alone read as a bag of facts. Built `Insight`
(sharpened repeatedly against overclaiming), inverted Security Questions
to be question-keyed rather than operator-keyed, then extended knowledge
gaps into testable `Hypothesis` objects.

**Roadblock — a hypothesis that can never resolve is worse than no
hypothesis.** Live DVAA runs surfaced a hypothesis permanently matched to
an operator whose only effect is HYPOTHESIZED, never CONFIRMED. Fixed by
requiring a CONFIRMED-capable effect before forming a hypothesis at all.

**Pivot 3 — optimization discipline: "every new abstraction must justify
its runtime and complexity."** Surfaced and fixed the insight-duplication
bug and produced the deterministic-extraction bypass. Explicitly rejected
in the same pass: parallel probe execution.

**Pivot 4 — away from self-built targets, toward real ecosystems.** Direct
cause of every target integrated since: DVAA's 19-agent fleet, the
official MCP filesystem reference server, DVAA's standalone consensus/
voting scenario. Each chosen only after live local verification.

**Roadblock — RAGBot and DVAA's real-LLM mode, both correctly abandoned.**
RAGBot's declared retrieval-poisoning vulnerability is documented but not
implemented in the simulator; DVAA's real-LLM backend has no Groq support
and the project has no paid OpenAI/Anthropic keys. Both set aside rather
than forced.

**Pivot 5 — "next capability, not next protocol."** Protocols are only
ways of observing behaviors that outlive protocols. Retired "which
protocol next" in favor of "which class of AI-agent behavior does Aginiti
not yet understand."

**Pivot 6 (2026-08-07) — RQ1 validates, it doesn't gate.** Explicit
decision: Phase 4 and beyond do not stay hard-gated behind RQ1 completing.
RQ1 proves whether the *current* planner beats today's baselines on
today's benchmark — valuable, but the project's actual objective is
bigger than one benchmark, and waiting on an operational quota constraint
would block real capability work. RQ1 moved from "gate" to "parallel
validation track," governed instead by the five principles. Also added an
explicit third vision pillar: "continuously learning from that
understanding," alongside understanding and exploiting.

**The mock-target planning pass (2026-08-07) — a real result, not
disqualifying, but not a win either.** With RQ1 no longer a gate, a
smaller-scale pass ran anyway on the mock target via a Gemini-backed
client built to route around the exhausted Groq quota. The honest result:
Aginiti tied Static-enumeration on success rate but took ~2.8x more
prompts, and didn't lead on breadth or security-relevant findings under a
tight budget. Traced to a specific, understood mechanism (the utility
schedule's early-campaign breadth-seeking costs prompts when a fixed order
already happens to be near-optimal for a given library), not treated as
disproof of the whole approach — but reported without spin, because that's
the standard this document holds itself to.

**Pivot 7 — a second real target, chosen for realism, not novelty.**
AnythingLLM — a real, actively-developed, production-shaped RAG/agent
platform — became the project's primary live target starting around
exp11. Unlike DVLA/DVAA (vulnerable-by-design fixtures), AnythingLLM is a
genuine production application; testing against it (and, later, a
self-built hardened gateway in front of it) is testing against something
closer to what an actual deployment looks like.

**Two real planning gaps found and fixed against live evidence, not
guessed at.** First, `emergent_impact` (an operator unlocking a valuable
but unnamed follow-on compromise was indistinguishable from a dead end —
found via a controlled offline experiment, fixed the same day). Second,
`chain_value` (a multi-step plant operator was structurally incapable of
outranking a mediocre single-step decoy regardless of its chain's real
value — found against real AnythingLLM evidence during the exp16-18
hardening chapter, fixed and regression-tested). Both closed a genuine
"the SSG knows something the planner's utility function can't see yet"
gap — the same category of bug, found twice, in two different places the
utility formula wasn't yet reading the graph correctly.

**Target hardening, twice — and a real fair external comparison.** Built
a self-hosted gateway (`aginiti/target_hardening/`) adding the controls a
real enterprise deployment would have — document sanitization, output
redaction, service-account tiers, adaptive lockout, rate limiting — across
two rounds, each live-verified against the actual running target, not
simulated. Then ran a real, fair, externally-verifiable comparison against
garak on the identical hardened target (exp19): 4 of 5 comparable
categories agreed exactly; the 5th was investigated at the trace level and
found not to be a fair comparison, reported as such rather than claimed as
a win.

**exp20 — the sharpest live result this project has produced.** A
150-trial benchmark against the same hardened target, 5 conditions
including a real Bayesian Thompson-sampling bandit. In a mission that
structurally requires completing a multi-step chain, Aginiti scored 3/15
real, ground-truth-verified compromises while every other condition —
including the Bayesian bandit — scored 0/15, and never attempted a single
chain operator across 120 combined trials. Real, mechanistic, not yet
statistically bulletproof at this sample size, and didn't generalize to a
broader mission shape. All three of those facts are reported together,
not separately.

**Multi-step discovery, composite scoring, and structured failure
feedback — the newest chapter (2026-08-12).** exp20's chains were all
human-authored, exact-key `Precondition` sequences — real evidence of
chain *execution* and *pivoting*, but not evidence Aginiti could
*discover* a path a human hadn't pre-wired. `ClassPrecondition` closes
that gap: an operator gated on a semantic tag (category, attack category,
or minimum severity) is unlocked by whichever upstream operator happens to
produce a matching claim, proven with a 6-step chain where either of two
interchangeable trust operators completes the identical downstream
sequence. Alongside it: composite severity-weighted scoring (a campaign
that never succeeds scores exactly 0, full stop — built to answer "which
system finds more *consequential* paths," not just more paths), a
graduated-difficulty benchmark pack that surfaced a real gap in the
Bayesian planner's severity-awareness, and a structured failure-diagnosis
taxonomy so a confirmed block can demote structurally similar candidates
instead of leaving no reusable signal behind.

**An independent engineering-hardening audit, on the same day, at explicit
request.** "Do NOT assume the architecture is correct just because 500+
tests pass." A from-scratch trace of the real execution path found the
project has **three parallel execution paths**, not one unified benchmark
harness — a real architectural characteristic, not previously stated
plainly anywhere. Found and fixed 5 real bugs, the most consequential
being that `ObservationAdapter.execute()` had zero exception handling
around the actual call to a target, meaning a target-side crash or
timeout could kill an entire campaign, and 3 of 4 real adapters were
relying on this not happening rather than protecting themselves. Fixed
once, at the one place every execution path funnels through, closing the
gap everywhere at once. Verified with a 10-scenario deterministic
end-to-end suite and a live smoke test against the real hardened
AnythingLLM target.

**Two more real targets, a fourth execution path, and three judge/oracle
bugs found the same way as everything above — by reading the postmortem,
not defending the prior result.** `hardened_agent`/`healthcare_agent`
(real RBAC, real redaction, real rate-limiting, real CUAD/CFPB document
corpora) were vendored to give the project a second production-shaped RAG
target independent of AnythingLLM. `run_full_assessment()` closed a
standing limitation rather than leaving it documented forever: the
adaptive-discovery engines (encoding/many-shot/framing/Crescendo) now run
as phases of one normal `AginitiPlanner` campaign over one shared graph,
not a separate, disconnected execution path. The live postmortem of that
first run found and fixed three real bugs (an LLM-judge false positive on
a canned "I can't share that" template, a fuzzy-oracle boilerplate
miscalibration, and a corroboration-gate blind spot that made system-
prompt leaks structurally unable to ever count as ground-truth-verified).
The Interrogation Attack (membership inference against a RAG corpus) was
implemented, worked on its first live run, then completely collapsed on
its second — root-caused to the exact same class of bug that would recur
one chapter later: real conversation-state contamination on a shared
server across trials the harness assumed were independent. Fixed
(fresh-server, MI-first ordering) and re-verified clean.

**exp28/29/30/31 — the same memory-contamination bug recurred at a larger
scale, this time in the RQ1 comparison itself, and got fixed for real
instead of documented as a known gotcha.** exp28 was the first live run
of RQ1's own 4-condition methodology against `hardened_agent`. Read
honestly rather than declared a win: Aginiti's live operator sequence
spent its entire budget on two attack families; 10 of its 12 trials
collapsed to zero real signal because every trial after the first shared
one long-lived server process and bearer key, so `hardened_agent`'s own
conversation-memory caution — a documented gotcha, never actually
mitigated — silently made trial N a measurement of "what happened after
50 prior attacks," not "how good is this policy." Two separate, real
planner gaps were root-caused from this (not one, and not "backwards" as
first suspected): `family_diversification_term` had no PROACTIVE reward
for a genuinely untried attack FAMILY, only a REACTIVE one that never
fires once the first family already has a success in it; and nothing at
all existed at the finer, WITHIN-family grain, where several of
`hardened_agent`'s own operators (5 `authority_claim_probe` wrapper
variants of one question, 3 `session_isolation_probe` variants, 2
`output_filter_evasion` variant groups) are near-duplicate hypotheses, not
independent techniques. Both fixed, each isolated and offline-proven
separately (exp30: 2/2 families touched vs. 1/2 before, every run at a
tight budget; exp31: both real findings recovered vs. 0/1 before) before
any live budget was spent confirming either. `experiments/_target_
lifecycle.py` closed the memory-contamination gap structurally (a real,
tested restart-before-every-trial mechanism, not a paragraph in a
quickstart guide), and exp29 re-ran RQ1's methodology correctly: 9 trials,
a genuine 3-persona sweep (persona is the real independent-trial axis for
`static`/`aginiti`, both fully deterministic given identical state — a
repeated seed would have been fake replication) instead of one persona
repeated 4x, fresh server restart before every single trial. It held
live: Aginiti won ground-truth success on all 3 personas (Random 2/3,
Static 1/3) and was the only policy to reach all 6 attack families in one
campaign. A follow-up audit — evidence only, every LLM-judge-only claim
excluded, keeping just the independent verbatim/fuzzy oracle — found 10
distinct real findings across the 9 trials: 2 genuine RBAC/authorization
crossings (`ops` receiving content never flagged `ops_visible`, via its
own aggregation probes) and 8 RAG/generation-guardrail over-disclosures,
while confirming the 5 dedicated authority-claim social-engineering probes
never once crossed the boundary they exist to test. Full detail: `docs/
EXP29_RESULTS.md`.

**Where this leaves us right now:** seven real, independently-developed
targets integrated and live-verified (five from earlier chapters plus
`hardened_agent`/`healthcare_agent`), plus a self-built hardened gateway
resembling a production deployment; the full evidence pipeline proven
end-to-end on all of them; a category taxonomy proven to generalize across
three structurally unrelated protocols; the full hypothesis lifecycle
proven live exactly once; two real planning gaps found and fixed against
live evidence in the exp16-18 chapter, and two more (proactive/within-
family diversification) found and fixed against live evidence in the
exp28/29 chapter; genuine multi-step discovery built and proven offline;
the strongest live evidence yet of a real planning advantage on TWO
separate real targets now (exp20's AnythingLLM result, exp29's
`hardened_agent` result); membership inference implemented, broken by
memory contamination, and fixed; and an independent audit that found the
architecture broadly sound but not yet unified across its four execution
paths. The original founding question — does Aginiti's planner beat the
baselines, at the frozen protocol's required scale — is still not
answered on the ORIGINAL DVLA protocol specifically, entirely because of
the Groq-quota roadblock, not because of any architectural doubt. exp29
is real, independent, live evidence toward the SAME underlying question on
a different, harder, real target — genuinely closer than this project has
ever been to answering it, while remaining honest that N=3 per condition
is not yet the frozen protocol's required scale. Per Pivot 6, none of this
is a precondition for capability work elsewhere in the roadmap.

---

## Principles for adding new capabilities

Every capability added from Pivot 6 onward is checked against all five
before it starts:

1. **Solves a limitation actually observed**, not one imagined in advance.
2. **Makes Aginiti better across many targets**, not tuned to one
   benchmark or one target's quirks.
3. **Improves understanding, planning, or exploitation** — not
   infrastructure for its own sake.
4. **Validated immediately against an existing real target** (or a
   controlled experiment where a live target isn't the right instrument),
   whenever possible, before moving to the next thing.
5. **Comparative claims need an experiment, not intuition.** If a
   capability is justified by "this should make Aginiti better than X,"
   that claim gets a citation in `docs/EVIDENCE_AND_EVALUATION.md` or it
   doesn't get made.

## Phase 0 — Adaptive planning substrate

_Phase status: infrastructure complete; the question it exists to answer
now has real, non-contradictory evidence pointing two different
directions depending on target and planner version — genuinely mixed, not
uniformly unresolved._

- Constrained-utility planner (9 additive terms as of this chapter),
  5-condition benchmark harness, resumable trial logging, Fisher's-exact
  comparison. **Proven** (built, unit-tested, exercised in multiple live
  runs).
- **The planner outperforms simpler baselines at a statistically
  meaningful sample size.** **Partially proven, evidence genuinely mixed.**
  Against the mock target with the pre-`chain_value` planner (2026-08-07),
  no — tied Static on success rate at ~2.8x the cost. Against a real,
  hardened AnythingLLM target with the current planner (exp20,
  2026-08-12), yes — a real, mechanistically-traced advantage on a
  chain-required mission, though not yet significant at the pairwise
  level (p=0.224) and not generalizing to a broader mission shape. The
  frozen DVLA-target RQ1 protocol itself is still unrun at a meaningful
  trial count — see `docs/EVIDENCE_AND_EVALUATION.md` §0/§5.

## Phase 1 — Behavior understanding

_Phase status: complete._

- Fact/Observation/Claim tiering, append-only provenance, confidence
  bands. **Proven** — live on all five real targets.
- Insight synthesis, grounded and dedup-guarded. **Proven** — live on
  DVLA, DVAA, DVAA-consensus, AnythingLLM.
- Target Profile as the primary product artifact. **Proven** — generated
  profiles on disk for every real target.
- Security Questions (question-keyed, evidence-aggregating). **Proven** —
  rendered in every generated profile.

## Phase 2 — Cross-protocol reasoning

_Phase status: current — proven three times, not just designed._

- A claim-category taxonomy that generalizes across protocols without
  being reinvented per target. **Proven** — `CATEGORY_TRUST_EDGE`
  confirmed live across mock/Slack, DVAA/A2A, and DVAA/consensus.
- Deterministic extraction as a general mechanism. **Proven** — live,
  zero-judge-call on MCP tool discovery, all filesystem-server operators,
  all 3 consensus operators.
- The graph *automatically* noticing a recurring pattern across targets
  without a human choosing the category tag. **Hypothesized.** Not built —
  every reuse so far was a deliberate human choice at operator-authoring
  time.

## Phase 3 — Hypothesis lifecycle

_Phase status: current._

- Persistent-identity, mutable Hypothesis object; get-or-create by
  normalized statement; wired into `assert_claim` for automatic revision.
  **Proven** — built, 17+ dedicated/integration tests.
- Full lifecycle (knowledge gap → formed hypothesis → tested → resolved).
  **Partially proven** — demonstrated live exactly once (DVAA consensus,
  ACCEPTED at confidence 0.80). Never demonstrated reaching REJECTED live.
  Accept/reject thresholds are uncalibrated v1 constants.
- Hypotheses interacting with each other. **Hypothesized.** Not modeled.

## Phase 4 — Exploit reasoning

_Phase status: the most active phase in the project right now — three
real, evidence-backed capabilities landed in this chapter alone._

- Multi-hop reasoning toward a KNOWN target. **Proven** — `path_progress`
  runs genuine BFS over the confirmed subgraph, recomputed every round,
  confirmed and unit-tested.
- **Consequence propagation toward an UNNAMED target (`emergent_impact`).**
  **Proven** (offline, 5 unit tests) — a real gap where a stepping-stone
  operator was indistinguishable from a dead end, found and fixed the same
  day. Honest scope: only helps once downstream structure has been
  established somewhere in the graph; a genuine cold start still can't be
  distinguished from a dead end.
- **Value-informed chain credit (`chain_value`).** **Proven, and now
  live-consequential** — found against real AnythingLLM evidence, fixed,
  and directly responsible for exp20's headline chain-pivoting result: in
  every one of 15 chain-required trials, `chain_value` is the mechanism
  that drove the planner to attempt a chain at all.
- **Genuine multi-step attack-path DISCOVERY (`ClassPrecondition`), not
  just execution of a pre-wired chain.** **Proven offline** — a real
  6-step chain where either of two interchangeable upstream operators
  unlocks the identical downstream sequence, with zero code changes
  elsewhere; a second, independently-authored pack (agentic primitives)
  cross-checks the mechanism generalizes. **Not yet proven live** —
  exp20's chains were pre-wired, not discovered; a live campaign against a
  target with genuinely undeclared topology is the natural next check.
- **Structured failure feedback (`failure_diagnosis` +
  `failure_evidence_penalty`).** **Proven offline** (an end-to-end ranking
  test proves demotion actually changes candidate order) — **not yet
  observed changing a live campaign's real behavior.**
- **Composite severity-weighted scoring.** **Proven on synthetic data**
  (a 300-trial Monte Carlo showing Aginiti wins less often but ~2x more
  consequentially than a fixed-order baseline) — **not yet applied to any
  real, already-reported campaign result.**
- Expected success probability per exploit path. **Hypothesized.** No
  probability model exists over exploit paths at all.
- Attack-graph search beyond shortest-distance (weighing multiple
  candidate paths against each other). **Hypothesized.** Likely subsumed
  by consequence propagation and `ClassPrecondition` once both are proven
  live together — revisit after, not before.

No longer hard-gated behind Phase 0 completing (Pivot 6) — governed by the
five principles instead.

## Phase 5 — Continuous learning

_Phase status: not started._

- Graph diffs (what changed between two campaigns against the same
  target). **Hypothesized.** Persistence exists; structured diffing does
  not.
- Cross-target learning (a pattern learned on target A changes how target
  B is approached, automatically). **Hypothesized.** See Phase 2's honest
  boundary above — this is the automatic version of what's currently a
  manual, human-driven taxonomy choice.
- Reusable exploit knowledge (an exploit-chain pattern proven on one
  target becomes a prioritized hypothesis on a structurally similar new
  target). **Hypothesized.** Depends on Phase 4's discovery work being
  proven live first.

## Phase 6 — Autonomous security scientist

_Phase status: not started; aspirational end-state, not a near-term
target._

- Proposes its own experiments (beyond ranking a fixed, human-authored
  operator library). **Hypothesized.**
- Validates hypotheses without a human choosing which operator tests which
  gap. **Hypothesized.** Today's gap-matcher is a human-designed heuristic
  operating over a human-authored library — a step toward this, not an
  instance of it.
- Updates beliefs and discovers genuinely new exploit classes (not
  pre-enumerated in any operator library). **Hypothesized.**

---

## The bigger picture

The founding bet of this project is that an evidence-grounded, persistent
graph — not a stateless prompt-and-score loop — is the right substrate for
understanding AI-agent security behavior, and that rigorous exploitation
should be a *consequence* of that understanding rather than a parallel
track. Five real, independently-developed targets across genuinely
different protocol surfaces, plus a self-built hardened gateway, have now
exercised that substrate without forcing an unplanned architectural
concept into the graph — every abstraction in `docs/ARCHITECTURE.md` §11
traces to a specific target or experiment that required it, and every
explicitly-considered addition that wasn't required was turned down with
the reasoning on record.

What the project has *not* yet done is close the loop back to the question
it started with, at the scale its own frozen protocol demands: whether
Aginiti's planner is a better planner than doing something dumber and
cheaper, measured against DVLA at a statistically meaningful trial count.
The evidence that exists instead — a real, mechanistically-traced planning
advantage on a different, real, hardened target (exp20) — is genuinely
strong but doesn't substitute for that specific unrun experiment. That's
not a failure of the architecture; it's an unrun experiment, blocked by a
mundane, well-understood operational constraint. Per Pivot 6, that no
longer blocks everything else — but running RQ1 to completion remains
worth doing for its own sake, and every capability added while it's
outstanding still has to clear the five principles above on its own, not
borrow justification from "the roadmap says this phase is next."
