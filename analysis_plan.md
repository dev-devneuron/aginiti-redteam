# Aginiti Phase 1 — Frozen Analysis Plan

Committed before any scored trial runs. Not to be edited after the benchmark
begins (see Stopping Rule). If a genuine bug is found mid-run, the run is
void: fix the bug, then restart from trial 1 under this same protocol
(unchanged) or an explicitly-versioned successor plan.

## RQ1 (primary)

Does an evidence-driven Security State Graph improve adaptive attack
campaign planning — measured as success rate, cost, and recovery-after-
failure — over static, random, and memory-guided operator selection,
against a real, independently-developed target?

This is not "does Aginiti always win." The claim under test is narrower:
does maintaining and reasoning over the SSG produce *measurably better*
campaigns than approaches that don't, on the specific target and mission
below.

## RQ1b (secondary, explanatory — only interpreted if RQ1 is supported)

If Aginiti beats the primary baselines, which term of the utility function
is doing the work? Decomposed via two additional planner variants that are
pure parameterizations of the existing formula (no new mechanism):
- Greedy-Information-Gain (alpha=1, beta=0, fixed)
- Greedy-Business-Impact (alpha=0, beta=1, fixed)

## Target

**Research target:** `WithSecureLabs/damn-vulnerable-llm-agent`, driven via
a `LangChainAdapter` implementing `BaseAdapter`. Chosen because: real,
independently developed (not owned by this project), known CTF pedigree,
already verified to run end-to-end against our own Groq keys with a real
LangChain `create_agent` pipeline (baseline query works; a blunt override
attempt is correctly refused — i.e. not a pushover target).

**Regression target:** the mock multi-system environment
(`aginiti/target/`). Used for CI/fast iteration only. Never scored as
evidence for RQ1 — that role ended when this plan was committed.

**Generalization target:** deferred. Not selected yet. Selection and
freeze happens only after RQ1/RQ1b conclude — see project memory / task
tracker for status, not this document.

## Operator design discipline

Operators for the DVLA adapter are written from publicly documented
technique classes (SQL injection via unsanitized string interpolation,
ReAct-loop / Thought-Observation hijacking, direct social-engineering
override of a stated restriction) — never reverse-engineered from the
exact vulnerable source line. Source reading is permitted only to build
the ground-truth oracle (`ground_truth_mission_achieved()`) and adapter
plumbing, never to hand-craft an attack payload matching an observed
implementation detail. Any capability that has no existing name in the
operator taxonomy and had to be newly invented for this target is logged
explicitly (see Capability Ontology Fit, below) — that's itself a result.

## Conditions (primary, RQ1)

Random, Static-enumeration, Memory-guided, Aginiti — same campaign loop,
same mission, same budget, same seed per trial index across all four
(`aginiti/campaign.py`, `aginiti/policies/`).

## Conditions (secondary, RQ1b)

Greedy-Information-Gain, Greedy-Business-Impact — only run and only
interpreted if the primary comparison supports RQ1.

## Metrics

- **Mission success rate** (per condition)
- **Cost to success**: total tokens spent, INCLUDING Aginiti's own planner/
  judge reasoning overhead, not just prompts sent to the target. Random/
  Static pay judge-call cost too (shared adapter), but Aginiti's
  information-gain/business-impact/path-progress computation is free
  (pure Python over the graph, no extra LLM calls) — this should be stated
  explicitly in the writeup so the comparison's fairness is checkable, not
  assumed.
- **Belief accuracy**: fraction of trials where the SSG's claimed outcome
  matched ground truth, checked independently of the SSG
  (`ground_truth_mission_achieved()`).
- **Decision efficiency**: operators considered / rejected / executed;
  signal efficiency (fraction of executed operators that confirmed at
  least one effect).
- **Branch efficiency**: for multi-path missions, how many operators were
  spent on branches other than the one that eventually won (or, for
  non-winning trials, how many distinct branches were attempted at all).
- **Recovery after failure** (primary explanatory metric — see below):
  number of steps between a confirmed defender-block (a DEFENDER-subgraph
  claim getting confirmed) and the next attempt on a *different* branch.
  Lower is better; this is the most direct operationalization of "adaptive
  planning reroutes, static planning doesn't."
- **Graph growth**: claims + observations over campaign steps.
- **Winning-path distribution**: which mission-success claim key was
  achieved, per condition (already implemented in `aginiti/report.py`).
- **Decision-trace quality** (human-rated): explicitly OUT of scope for
  this phase. Expensive, needs independent raters, deferred.

## Judge validation

Before the scored run: sample ~30-50 raw transcripts from prior
(unscored) shakedown runs. A labeler blinded to condition, operator id,
and planner name labels each transcript against the same candidate-effect
questions the judge was asked. Compute agreement rate between blind
human labels and the judge's `confirmed_effect_ids`. Report this number in
the writeup regardless of outcome. If agreement is poor, RQ1 results are
not trustworthy regardless of what they show, and this must be fixed
before the scored run, not after.

## Sample size

Target: 20 trials per primary condition (80 campaigns), 10 trials per
secondary condition (20 campaigns) if RQ1b is reached. Based on this
session's measured real cost (~15-20k tokens/campaign against the mock;
DVLA campaigns expected in a similar range), total budget is
approximately 1.5-2M tokens — small enough to run over a few days even
under the current shared-org rate-limit constraints, unlike any
multi-target/multi-framework scope.

This is an honestly modest, exploratory-power sample, not a
high-power confirmatory study. The writeup will say so explicitly rather
than imply more statistical power than 20/condition provides. Effect
size, not just p-value, will be reported (Fisher's exact for success
rate; the existing `aginiti/stats.py` module already flags underpowered
results rather than overstating them).

## Statistical tests

- Success rate: Fisher's exact, two-sided (`aginiti/stats.py`, already
  validated against the textbook reference value).
- Cost / efficiency / recovery-after-failure distributions: Mann-Whitney U
  (non-parametric — no assumption these are normally distributed, and
  they likely aren't given small n and skew toward budget exhaustion).

## Capability ontology fit (tracked, not just discussed)

When the DVLA operator library is written, record: how many of its
operators mapped onto an existing named capability from the mock
environment's taxonomy (ReconCapability, ToolDiscovery, TrustProbe,
IndirectInstructionInjection, ApprovalWorkflowProbe, etc.) vs. how many
required inventing a new capability type. This is itself a result about
whether the abstraction generalizes, independent of RQ1's outcome.

## Stopping rule

Run exactly once under this protocol. No adjusting the utility function,
operator library, or judge prompt based on interim results. A discovered
bug voids the run; fix, then restart at trial 1 under this same
(unmodified) protocol. Do not patch-and-continue mid-experiment — today's
shakedown runs (which did patch-and-continue) are explicitly NOT the
scored run for exactly this reason.

## Failure criteria (stated in advance)

RQ1 is NOT supported if Aginiti's success rate and recovery-after-failure
do not show a meaningful advantage over BOTH Static and Memory-guided
(beating Random alone is not sufficient — that's the floor baseline).
A negative result under this protocol is reported as such. Per the
project's own prior discussion: a rigorously-measured negative result here
is more valuable than an unexamined positive claim, because it directly
tells us whether to redesign the planner while keeping the SSG, rather
than leaving that ambiguous.

## Known threats to validity (stated in advance, not discovered later)

- **Judge reliability**: the SSG's beliefs are only as good as an LLM's
  interpretation of ambiguous natural-language evidence. Two real bugs in
  this exact mechanism were found and fixed earlier in this project's
  development (an effect-clobbering bug and a judge-polarity bug) —
  direct evidence this is a real risk, not a hypothetical one. Mitigated
  by the blind judge-validation step above, not eliminated by it.
- **Operator/target co-design**: operators were designed with knowledge of
  DVLA's general vulnerability class (not its exact source, per the
  discipline above) — this is a single-target study; it says nothing yet
  about generalization to an unseen target. That's explicitly deferred to
  a later, separate held-out-target phase under its own frozen protocol.
- **Ecological validity**: DVLA is a deliberately-vulnerable CTF app. A
  positive result licenses the claim "Aginiti finds this path more
  efficiently than these baselines on this target," not "Aginiti
  compromises real enterprise systems."
- **Single-team evaluation**: implementer, evaluator, and judge-designer
  are the same people. No independent replication exists yet. The frozen
  protocol and blind judge labeling are the primary mitigations available
  at this project's current scale.
- **Cost accounting**: Aginiti's own reasoning overhead is structurally
  cheaper than an LLM-based planner would be (pure Python over the graph),
  which is a genuine advantage of the design — but this must be stated
  explicitly, not silently baked into a "cost" number that looks like an
  apples-to-apples comparison without the caveat.
