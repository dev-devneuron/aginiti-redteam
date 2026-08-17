# Aginiti — Evidence & Evaluation Ledger

_Last rewritten 2026-08-13. This is the citation trail behind every claim
made in `docs/AGINITI_OVERVIEW.md` and `docs/ARCHITECTURE.md`. No status
below is upgraded without a specific experiment, live-run artifact, or test
citation attached to it — where evidence is missing or thin, that's stated
plainly, not implied away._

---

## Executive summary

*Read this section alone and you have the complete evidentiary picture —
everything below is the citation trail behind each line.*

- **The vision this is scored against:** build the best system for
  understanding a target AI system's real security behavior through
  interaction, continuously learning from that understanding, and
  rigorously exploiting confirmed weaknesses.

- **What's proven, in one line each (§1):** the Fact/Observation/Claim/
  Insight pipeline works live on five real targets. Deterministic,
  zero-LLM-call extraction matches or beats the LLM judge (7/7 agreement
  after a targeted fix). A trust-recognition category (`CATEGORY_TRUST_EDGE`)
  has generalized, unmodified, across three unrelated protocols. Letting a
  campaign keep learning after a compromise instead of stopping surfaced
  findings that stopping early would have missed entirely. The Hypothesis
  lifecycle has been proven end-to-end exactly once. A real planning gap —
  an operator that unlocks an unnamed-but-valuable compromise being
  indistinguishable from a dead end — was found and fixed offline, then a
  second real gap (a multi-step plant operator structurally incapable of
  outranking a mediocre decoy) was found and fixed against a live target.
  Multi-step attack-path *discovery* (not just execution of a pre-wired
  chain) now works via `ClassPrecondition`, demonstrated with a real 6-step
  chain and two mutually-substitutable trust operators.

- **The sharpest live result to date — a real planning advantage, not just
  a mechanism:** a 150-trial live benchmark against a hardened, production-
  realistic AnythingLLM target (`exp20`, §0) found that in a mission
  requiring a multi-step chain to win, **Aginiti scored 3/15 (20%) real,
  ground-truth-verified compromises while Random, Static-enumeration,
  Greedy-Information-Gain, and a real Bayesian Thompson-sampling bandit all
  scored 0/15.** No other condition ever attempted a single chain operator,
  in either mission, across 120 combined trials. This is real,
  mechanistically-traced evidence — not yet a statistically bulletproof
  result at this sample size (pairwise Fisher's-exact p=0.224; pooled
  baselines p=0.0067), and it did not generalize to a broader "any
  compromise counts" mission (0% for every condition there). Both facts are
  reported, not hidden.

- **What the *frozen* RQ1 protocol (DVLA, mock-target) shows — stated
  plainly, still not a clean win there:** run for real on 2026-08-07
  against the *mock* target (n=3-5, a small-sample pass, not the frozen
  protocol itself), Aginiti tied Static-enumeration on success rate (100%
  vs. 100%) but took **~2.8x more prompts to get there** (14.0 vs. 5.0),
  and did not lead on breadth or security-relevant findings under a tight
  budget either. This result and exp20's are about *different* targets and
  *different* planner versions (exp20 postdates the `chain_value` fix) —
  they are not in tension, but neither substitutes for the frozen
  DVLA-protocol RQ1 run, which has still never completed at a meaningful
  trial count (Groq API quota, an operational not architectural
  constraint).

- **Targets evaluated (§2):** `damn-vulnerable-llm-agent` (both known
  attack vectors currently blocked — a real negative result), DVAA's
  memory/A2A/MCP surfaces (cross-session memory persistence confirmed,
  unauthenticated tool execution confirmed, identity spoofing confirmed),
  the official MCP filesystem server (boundary enforcement held against
  both traversal styles), DVAA's consensus/voting scenario (single-identity
  outcome manipulation confirmed, full hypothesis lifecycle proven), and
  **AnythingLLM** — a real, production-shaped RAG/agent platform, tested
  against a self-built hardened gateway across two hardening rounds, four
  real multi-step exfiltration chains (up to L5), and a 150-trial planner
  comparison.

- **How Aginiti compares to existing tools (§4):** garak and PyRIT's
  systematic-probing strategy is directly reimplemented as the
  `Static-enumeration` baseline; AutoRedTeamer's attack-outcome memory as
  the `Memory-guided` baseline. A real, fair, externally-verifiable
  comparison against garak itself (not just its strategy) ran on the
  identical hardened target: 4 of 5 comparable categories agreed exactly
  (0% attack success both tools); the 5th (encoding) was investigated at
  the trace level and found not to be a fair comparison — see `docs/
  COMPETITOR_COMPARISON.md`.

- **What would make each weak claim strong (§5):** RQ1 at the frozen
  protocol's trial count; a larger N specifically for exp20's chain-required
  mission; blind human validation of judge/insight quality; hypothesis-
  threshold calibration; a live-target validation of the agentic-primitives
  pack; a sixth target to test whether the category taxonomy keeps
  generalizing.

- **For every term used above**, see `docs/ARCHITECTURE.md`'s Glossary. For
  the story of how the project got here and what's next, see `docs/
  ROADMAP.md`.

---

## Why this approach — what grounds it, and what's still just motivated by it

Two different kinds of support show up in this document, and they should
never be read as the same strength of claim. **Proof** means an experiment
in §0 or a live-run citation in §1 — something Aginiti's own team measured.
**Motivation** means external research or established practice that argues
the *design* is reasonable — not evidence that Aginiti's specific
implementation outperforms anything. Every item below is labeled which kind
it is.

**The core architectural bet, and why it's motivated rather than assumed.**
Aginiti's founding argument (from the original Aginiti Design Document
v1.0's Motivation section) is that classical security testing — and by
direct extension, static prompt-injection scanners — rests on an
assumption agentic AI systems break: that the target's reachable state
space is fixed and can be enumerated in advance. An agentic system's
behavior, memory, tool availability, and retrieved context all change at
runtime, so a fixed attack library can never be exhaustive by construction
— the only way to discover a state no operator anticipated is to interact
with the specific target and track what comes back. This reframing — model
the *environment*, not a library of *attacks* — is why the SSG exists at
all, and why `ClassPrecondition` (§1, "Multi-step discovery") exists on top
of it: even a graph-shaped memory is only as good as its ability to wire
together things a human didn't pre-declare. This is directly consistent
with how the security field itself has been moving: OWASP's Agentic
Security Initiative defines risk categories (goal hijacking, tool misuse,
identity abuse, memory poisoning, insecure inter-agent communication) that
only make sense once a system has state and tools, not just a text-in/
text-out boundary, and MITRE's ATLAS knowledge base has expanded
specifically to cover multi-agent trust exploitation. **This is
motivation, not proof** — it argues the SSG approach is worth testing,
which is exactly why RQ1 and exp20 are the load-bearing evidence, not
intuition.

**Where Aginiti sits relative to specific existing tools — and what's
actually been measured vs. only architecturally distinguished:**

| Tool | What it solves well | What it doesn't model | Aginiti's relationship to it |
|---|---|---|---|
| **garak** (Derczynski, Galinkin, Martin, Majumdar & Inie, 2024, arXiv:2406.11036) | Systematic, repeatable LLM probing across dozens of vulnerability categories via a probe/detector architecture. | No persistent model of a specific deployment's tools, memory, or trust relationships across probes; a REST-generator-based scanner structurally cannot observe real tool invocation or confirmed network egress. | Its strategy is reimplemented as the `StaticPolicy` baseline; a real head-to-head against the actual tool ran on the identical hardened target (`docs/COMPETITOR_COMPARISON.md`) — 4/5 comparable categories agreed exactly. |
| **PyRIT** (Lopez Munoz et al., 2024, arXiv:2410.02828) | Composable, model-agnostic multi-turn adversarial orchestration (Crescendo, TAP, and others); used operationally by Microsoft's AI Red Team. | Independent evaluation has identified gaps in agent state tracking and long-horizon behavioral analysis for agentic targets — the exact gap the SSG targets. | Its `PromptConverter` architecture is reused (`aginiti/transforms/converters.py`); `StaticPolicy` is representative of its systematic-probing class, not a benchmark against PyRIT itself. |
| **AutoRedTeamer** (Zhou et al., 2025, arXiv:2503.15754) | Automated, continuously-updated attack-technique coverage via memory-guided attack selection. | Its memory is *attack-outcome* memory (what worked before), not *target-state* memory (what exists in this specific deployment). | Reimplemented as the `MemoryGuidedPolicy` baseline — scored 0/15 on exp20's chain-required mission, never attempting a chain in any trial. |
| **BloodHound / attack-graph tooling** (lineage: Swiler & Phillips, 1998, Sandia; Lippmann & Ingols, 2005, MIT Lincoln Lab) | Multi-hop shortest-path attack-chain reasoning over an *ingested*, statically-collected graph. | Not built from live interactive probing, and not applied to conversational AI targets at all. | `path_progress`/`chain_value`/`ClassPrecondition` run the same real BFS-over-a-graph idea, but the graph is built from live evidence and, as of `ClassPrecondition`, can *discover* chain topology rather than only consume a pre-collected one. |
| **AgentFuzz / AgentPoison** (Chen et al., 2024) | Directed fuzzing and memory-poisoning attacks that discover concrete agent-specific vulnerabilities. | Vulnerability-*discovery* mechanisms, not campaign planners. | Complementary, not competing — a plausible future *operator source*, not something Aginiti currently integrates. |
| **MITRE ATLAS / D3FEND / ATT&CK, OWASP LLM Top 10 / Agentic Security Initiative** | Structured, community-maintained taxonomies of adversarial tactics and agentic risk categories. | Human-readable classification, not machine-executable, and not tied to any specific deployment's observed state. | Aginiti's `CATEGORY_*`/`attack_category`/`owasp_llm_category`/`mitre_atlas_technique` tags compile elements of these into an executable substrate. |
| **AI-SPM platforms** (Noma, Zenity, Orca, Microsoft Defender for Cloud AI-SPM) | Continuous, passive configuration discovery and compliance-framework mapping. | Cannot perform adversarial validation — report what's configured, not what's actually reachable. | Out of scope by design — Aginiti doesn't compete here at all. |

**Research that motivates specific mechanisms, not just the overall
framing** — the planning-under-uncertainty framing (Sarraute, Buffet &
Hoffmann 2011), provenance modeling (W3C PROV-O), indirect prompt
injection as a threat class (Greshake et al. 2023), multi-agent/
coordination threats (NetSafe, arXiv:2510.06445), automated adversary
emulation (Applebaum et al., MITRE), and — new since `chain_value` was
built — potential-based reward shaping (Ng, Harada & Russell 1999;
Wiewiora, Cottrell & Elkan 2003) and Bayesian fixed-budget best-arm
identification (Atsidakou et al. 2022/2024) for the Bayesian planner
variant. Full citation list with exact papers and what each motivates:
`docs/RESEARCH_AND_PROVENANCE.md` §5.

**What none of this literature does:** prove that Aginiti's specific
implementation works. It establishes that the *problem framing* is one the
field already takes seriously. Whether this particular system's execution
of that framing actually beats simpler alternatives is exactly what §0's
experiments test.

---

## Vision

> Build the world's best system for understanding the real security behavior
> of AI agents through interaction, continuously learning from that
> understanding, and rigorously exploiting confirmed weaknesses.

Everything below is scored against that sentence, in the order it's
written: understanding first, exploitation as a consequence of
understanding, not a separate track. "Continuously learning" is a third
pillar alongside understanding and exploiting, not a new goal. Two things
follow from taking this seriously: a finding of "no exploitable weakness"
is a complete, valuable answer in its own right (`target_profile.py`'s own
design principle), and the frozen DVLA-protocol RQ1 is a parallel
validation track for the planner specifically, not a gate the rest of this
list waits behind.

---

## 0. Controlled experiments

Everything in this section is a **designed experiment**, not an incidental
observation from a live run built for another purpose. Each one names a
precise hypothesis, a competing baseline, a metric, the actual
implementation (a script under `experiments/`, runnable and re-runnable),
the real results, and a significance test where the design supports one.
Every experiment writes its raw numbers to `experiments/results/<name>.json`
or a `runs*/` directory, so a citation elsewhere in this document can
always be traced back to the exact data that produced it.

### Offline / deterministic experiments (zero cost, arbitrarily repeatable)

**Experiment 1 — does gap/hypothesis priority actually change planning,
and does it help under a tight budget?** `AblatedPlanner` (gap/hypothesis
priority hard-zeroed) vs. full `AginitiPlanner`, 300 synthetic worlds,
business_impact/path_progress structurally neutralized so only the ablated
terms can differentiate ranking. **Result:** gap-linked operators resolved
within budget — FULL mean 0.668 vs. ABLATED mean 0.507 (sign test,
190/211 non-tied pairs favor FULL, p<0.0001). Hypothesis-linked — FULL mean
0.999 vs. ABLATED 0.484 (297/297 non-tied pairs favor FULL, p<0.0001).
Total operators resolved per trial was identical between conditions — a
pure ordering effect, no throughput cost. **Status: Proven**, for the
mechanism in isolation (`experiments/exp1_hypothesis_gap_priority_ablation.py`).

**Experiment 2 — does deterministic extraction actually save an LLM call
while matching the judge's own verdict?** Deterministic extractor vs. LLM
judge, same raw response, 7 real operators against the MCP filesystem
server and DVAA consensus server. **First run:** 6/7 agree (86%) — the
judge missed a compound effect the extractor caught. **Fix applied**
(judge prompt sharpened to evaluate every candidate effect independently).
**Re-run against identical evidence: 7/7 agree (100%).** Zero LLM calls
for the extractor path in all 7 cases vs. 7 judge calls (28.0s → 6.6s after
the fix, for the same 7 calls). **Status: Partially proven, strengthened**
— the zero-LLM-call claim is unconditionally proven (structural); the
reliability claim has a before/after data point on real evidence but is
still n=7 against two target types (`experiments/exp2_deterministic_vs_judge.py`).

**Experiment 5 — does the graph keep improving after the mission is
already satisfied?** Retrospective analysis of a live 7-operator DVAA run:
the mission was first satisfied at claim index 3 of 16. At that point only
2 distinct claim keys were resolved and 2 security-relevant findings
existed; by the end of the same run, 6 distinct claim keys and 4
security-relevant findings — continuing past the satisfied mission
surfaced **2 entirely new, independently-severe compromises** a
`stop_on_mission_success=True` campaign would never have reached. Of 8
grounded insights synthesized, only 2 could have come from
pre-satisfaction evidence alone. **Status: Proven for this one real, cited
case** — a single data point, not a sampled comparison
(`experiments/exp5_graph_improves_after_compromise.py`).

**Experiment 7 — what does "multi-step exploitation" actually require?**
Rejected the obvious hypothesis first ("the planner can't reason more than
one hop ahead") by checking `path_progress`/`target_graph.py` directly —
multi-hop BFS reasoning toward a *known* target already worked. The real
gap: `probe_admin_panel` (unlocks a follow-on worth 5x the mission target's
weight) and `probe_decommissioned_endpoint` (a genuine dead end) scored
**identical utility (1.000)**, because `business_impact`/`path_progress`
are computed strictly against `Mission.success_criteria`, a tuple fixed at
authoring time — the follow-on was never named there. **Fix:**
`emergent_impact()`, the same BFS mechanism run against every
`mission_outcome`-tagged claim key the library itself recognizes. **After
the fix:** at a genuine cold start the gap is structurally unchanged (the
graph never assumes connectivity it hasn't earned — the same character
`path_progress` already has); once the downstream edge is established
elsewhere in the graph, `probe_admin_panel` now scores `emergent_impact=
3.000`, `utility=1.150` vs. the dead end's `0.000`/`1.000`. **Status:
Proven** for both the original gap and the fix's bounded effect — 5 new
unit tests, an honest scope limit (only helps once downstream structure
exists somewhere in the graph) stated explicitly
(`experiments/exp7_consequence_propagation_gap.py`).

**Multi-step discovery, composite scoring, and structured failure feedback
— four more offline experiments (2026-08-12), full detail in `docs/
MULTI_STEP_DISCOVERY_AND_SCORING.md`:**

- **`ClassPrecondition` discovery-chain dry run**
  (`experiments/discovery_chain_dry_run.py`): a real 6-step chain with
  every operator past stage 1 gated only by semantic tag, run twice with
  either of two interchangeable "establish trust" operators suppressed —
  **both runs reach full L5 exfiltration through the identical downstream
  operators**, proving the discovery is real, not just a differently-
  labeled hardcoded chain. A real cost-accounting bug was found and fixed
  in the process: hub-node traversal was initially double-counted as a
  real operator hop, wrongly pruning a genuinely completable chain as
  infeasible at budget=8 — fixed with a proper 0-1 BFS, verified with a
  budget sweep (budget 6: correctly infeasible; budget 7-8: correctly
  succeeds, was wrongly `SEARCH_EXHAUSTED` before the fix).
- **Composite-scoring Monte Carlo** (`experiments/
  graduated_difficulty_dry_run.py`): N=300 trials/policy, budget=7 against
  a 5-candidate table (A–E) whose true success probability exists only in
  a mock adapter's random draw, never on any Operator field a planner can
  read. **Result:** Aginiti wins the raw success-rate race less often
  (77.0% vs. Static's 98.0%) but scores nearly 2× higher on the composite
  metric (mean 0.0315 vs. Static's 0.0166), because it commits to the
  highest-severity candidate (C, L5) every single trial while Static always
  takes the cheapest, highest-probability one (A, Medium severity). A real,
  previously-undocumented gap was also surfaced: `BayesianPlanner` has no
  cost/severity awareness in this scenario at all, reducing to an
  effectively uniform random first pick. A real bug in the scorer itself
  was caught by this experiment and fixed: `mission_success` had silently
  capped every "any"-mode win at 0.2 by using a fractional formula meant
  for "all"-mode missions — fixed to a strict boolean, locked in with a
  regression test.
- **Structured failure-diagnosis end-to-end test**
  (`tests/test_failure_diagnosis.py`): proves `failure_evidence_penalty`
  actually changes ranking order between two otherwise-identical candidates
  sharing a confirmed, generalizable block — not just that the taxonomy
  tags exist.
- **Agentic-primitives dry run** (`experiments/
  agentic_primitives_dry_run.py`): the approval-gate/untrusted-tool-output
  pack, composed via `ClassPrecondition` in a second, independently-
  authored pack — a cross-check that the discovery mechanism generalizes
  rather than being overfit to its original demonstration. Produces this
  project's first real usage of the `blocked_by_approval_gate` failure
  diagnosis on a suppressed bypass attempt.

**Status of all four: Proven for the mechanism, offline.** None has been
run against a live target yet — the agentic-primitives pack in particular
is explicitly deferred pending target-specific validation (§5).

**exp30/exp31 (2026-08-14) — do the two new exploration-term fixes causally
change ranked behavior, isolated from each other and from every other
planner term?** Built specifically to answer this BEFORE spending any live
budget confirming either fix, after a live postmortem (exp28) motivated
both. Each scenario was rejected and rebuilt at least once after being
found to accidentally let something OTHER than the fix under test explain
the result — see each experiment script's own module docstring for the
specific confound found and removed, disclosed rather than silently fixed.

- **exp30 (cross-family fix, `PROACTIVE_COVERAGE_BONUS`)**: a synthetic
  2-family scenario sized to `hardened_agent`'s real family counts (15/26
  members), at a budget (10) comfortably inside the first family's own
  size. Pre-fix code and the fully non-adaptive `StaticPolicy` checklist
  perform identically narrow (1 of 2 families touched, 0% reaching the
  second); post-fix code touches both families every run (100%), matching
  `RandomPolicy`'s breadth (n=20) while beating its reliability (Random
  found the real finding only 80% of the time; post-fix Aginiti, 100%).
  **Status: Proven offline**, isolated (`experiments/exp30_offline_
  planner_fix_validation.py`, locked in by `tests/test_family_coverage_
  scenario.py`).
- **exp31 (within-family fix, `technique_cluster_diversification`)**: a
  synthetic single-family scenario (deliberately single-family, so
  `family_diversification` cannot contribute to the result at all) with a
  5-member near-duplicate cluster (weight 8, matching the real authority-
  claim-probe boundary-crossing potential) alongside 3 genuinely distinct
  singleton techniques (weight 3, matching `system_prompt_extraction`'s
  real weight). At budget=5 (the cluster's own size), pre-fix code and
  `StaticPolicy` never reach the singleton techniques at all (0/1 both-
  findings recovered); post-fix code reaches them every run (1/1),
  finding both real hypotheses deterministically, vs. Random's 35% (n=20).
  **Status: Proven offline**, isolated (`experiments/exp31_offline_
  cluster_fix_validation.py`, locked in by `tests/test_technique_cluster_
  diversification.py`).

Both fixes were subsequently confirmed live in exp29 (`docs/EXP29_
RESULTS.md`) — the offline scenarios predicted the live behavioral change
correctly (visibly broader family/technique sampling in exp29's actual
operator sequences) before any live budget was spent finding that out.

### Live experiments against the mock target (2026-08-07, real Groq/Gemini calls)

Unblocked via a Gemini-backed client (`aginiti/gemini_client.py`) built
specifically to route around Groq's exhausted pooled-key quota. **These
results are against the mock target — explicitly NOT the frozen RQ1
protocol** (which targets DVLA, currently uninformative since both its
known attack vectors are blocked).

**Experiment 4 (cost-to-success, n=5, budget=15, 3 conditions):**

| Condition | Success rate | Mean prompts to success | Mean operators considered |
|---|---|---|---|
| Random | 40% (2/5) | 12.5 | 76.0 |
| Static-enumeration | 100% (5/5) | **5.0** | 30.0 |
| Aginiti | 100% (5/5) | 14.0 | 78.0 |

Aginiti beat Random on success rate but not significantly at this sample
size (Fisher's exact, p=0.167). Aginiti tied Static-enumeration on success
rate and took **~2.8x more prompts to get there** — traced to a specific
mechanism, not unexplained: Static's fixed order happens, for this
library, to front-load a short, complete attack chain, while Aginiti's
early-campaign `alpha` weighting spends budget on breadth by design before
converging on the same chain. **A real result that does not favor Aginiti
on cost, reported plainly.**

**Experiment 3 (breadth under budget=10, n=3, 5 conditions):** Exploit-first
and BFS-only planner variants never took a single step in any trial (no
operator has positive business_impact/path_progress at a cold start,
without an information-gain term) — real evidence that *some*
information-seeking incentive is necessary to bootstrap a campaign at all,
even though it's the current utility schedule's cost, not ranking logic,
that explains Experiment 4's gap. Among the conditions that actually ran,
Static resolved more distinct claims (8.00 vs. Aginiti's 6.33) and was the
only condition to reliably confirm security-relevant findings (3.00 every
trial vs. Aginiti's 0.00) under this tight budget.

**Experiment 6 (cross-protocol trust query):** `trust_assumptions()`
correctly surfaced a CONFIRMED trust-edge finding identically across all
three real graphs tested (mock/GitHub, DVAA, DVAA consensus) — the
taxonomy/query layer generalizes, unaffected by the other two experiments'
findings.

**Overall status of this pass:** real signal, honestly reported, **not**
the frozen RQ1 protocol and nowhere near its required trial count (n=3-5,
one target, one library, one seed range). What it responsibly justifies:
revisiting the alpha/beta early-campaign schedule against a cost objective
— not "Aginiti is proven better," which this data doesn't show.

### Live experiments against AnythingLLM (exp11 onward — the project's
### primary live target since this chapter began)

**exp16 (tight-budget validation, multi-branch mission):** the planner
reliably found "one extremely reliable winner" — real evidence of correct
discrimination, but on a comparatively easy problem. Became the direct
motivation for hardening the target further rather than declaring victory.

**The `chain_value` fix (found and fixed against real evidence):** a
multi-step plant operator was structurally incapable of ever outranking a
mediocre single-step decoy, regardless of the chain's real downstream
value — the same shape of gap Experiment 7 found and fixed for
`emergent_impact`, but for chain-position credit specifically. Fixed and
regression-tested in `aginiti/planner/aginiti_planner.py`.

**exp17/exp18 (hardened AnythingLLM target, two rounds):** real, live-
verified production-hardening — document sanitization, output redaction,
service-account tiers, adaptive lockout/rate-limiting, strengthened system
prompt, raised RAG similarity threshold. `tool_inventory_full_disclosure`
leaked 50.7% of the time (38/75) under an unguarded "integration audit"
pretext before the round-2 system-prompt fix — a real finding that directly
motivated a fix any production admin would make. Full build log: `docs/
HARDENED_TARGET.md`.

**exp19 (Aginiti vs. garak, live, same hardened target):** 4 of 5
comparable categories agreed exactly (0% attack success both tools — the
hardened target genuinely held). The 5th (encoding) was investigated at the
trace level and found not to be a fair comparison — garak's own detector
scores "success" on decode-and-echo compliance, not on hidden-instruction
execution. A real upstream bug (AnythingLLM's Gemini safety-filter response
crashing the request instead of refusing cleanly) was found and fixed at
the gateway layer during this run, benefiting every future caller through
it. Full numbers: `docs/COMPETITOR_COMPARISON.md`.

**exp20 (full-scale planner benchmark, live, same hardened target — the
project's sharpest current result):** 150 real campaigns, 5 conditions
(Random, Static, Greedy-Information-Gain, Bayesian, Aginiti),
N=15/condition, 28-operator library, budget=4, two missions.

- **Chain-required mission: Aginiti 3/15 (20%), every other condition
  0/15.** Broad mission: all 5 conditions 0/15.
- Mechanism, fully traced: in every one of Aginiti's 15 chain-required
  trials, `chain_value` drove it to attempt the RAG-injection chain first;
  the target's L1 defense blocked it every time (0/15 RAG successes); the
  campaign kept going and pivoted its remaining budget into a second chain
  (automatic-mode tool-exfiltration or markdown-image exfiltration),
  succeeding 3 times. No other condition ever attempted a single chain
  operator in either mission, across 120 combined trials.
- Statistical significance: pairwise Fisher's-exact p=0.224 (underpowered
  at N=15); pooling all 4 baselines, p=0.0067 (a secondary,
  assumption-laden view). Real and mechanistically explained; not yet
  bulletproof at this N.
- Zero false positives — every one of Aginiti's 3 wins cross-checked
  against the independent, listener-log-based ground-truth oracle, not the
  judge or the SSG's own belief.
- The discovery-arm bonus test (N=10, `encoding_discovery` +
  `framing_discovery`) failed to crack the target's system-prompt defense
  in 10/10 trials — a genuine null result and a positive signal about the
  hardening work.
- **Status: Proven, for a real, mechanistically-traced, ground-truth-
  verified planning advantage on a real target — the strongest such
  evidence this project has produced. Not yet statistically bulletproof at
  N=15, and does not generalize to the broader mission shape.** Full
  10-metric breakdown: `docs/EXP20_RESULTS.md`.

**Overall status across both the mock-target pass and the AnythingLLM
chapter:** RQ1's underlying question — is Aginiti's planner better than
simpler baselines — has two honest, non-contradictory answers depending on
which evidence you're reading. Against the mock target with the
pre-`chain_value` planner (2026-08-07), the answer did not favor Aginiti on
cost. Against a real, hardened, production-shaped target with the current
planner (exp20), the answer is a real, mechanistically-traced advantage
specifically on missions that reward multi-step chain investment. **Neither
result substitutes for the frozen DVLA-protocol RQ1 run**, which remains
unrun at a meaningful trial count — see §5 and `docs/ROADMAP.md`.

---

## 1. What has actually been demonstrated, per capability

For each capability: what was built, where it was tested, what evidence
exists, and what remains unproven. "Tested" distinguishes **offline unit
tests** (no network/LLM calls, regression-grade) from **live runs** (a real
target, costs tokens, the only evidence the mechanism works against
something Aginiti doesn't control).

### Facts, Observations, Claims

Built (`aginiti/graph/schema.py`, `ssg.py`), tested (`test_ssg.py`,
`test_observation_adapter.py`, `test_graph_queries.py`), live on all five
real targets — every `runs*/` graph on disk contains the full Fact/
Observation/Claim log. **Unproven:** Facts have never been used for
anything beyond `observed_tools()` and audit-trail display; the confidence
model driven by Observations has never been validated against ground truth
of "how confident should this actually be."

### Insights

Built (`InsightCategory.BEHAVIORAL/SECURITY/KNOWLEDGE_GAP`,
`synthesize_insights()`, dedup guards), tested (21 tests,
`test_insights.py`), live on DVLA/DVAA/DVAA-consensus/AnythingLLM — a real
duplication bug (≈13 near-duplicate insights per DVAA campaign) was found
by running a live campaign and fixed, down to 4 distinct. **Unproven:**
insight *quality* has never been scored by an independent human rater; the
MCP filesystem server run produced genuinely thin insights, honest evidence
that synthesis quality is bounded by how much the operator library actually
exercised.

### Hypotheses

Built (`hypothesis.py`, `_find_resolving_chain()`'s bounded BFS through the
full precondition graph — fixed after a live DVAA run surfaced a plant-
then-recall pattern the original single-operator matcher couldn't handle),
tested (11 dedicated tests + 6 integration tests + hypothesis-formation
tests), live evidence of the **full lifecycle** (form → test → resolve)
exactly once: the DVAA consensus run, reaching ACCEPTED at confidence 0.80
within a single 3-round campaign. **Unproven:** accept/reject thresholds
(0.8/0.2, ±0.25 step) are uncalibrated v1 constants; a hypothesis has never
been REJECTED live; multi-hypothesis interaction is not modeled.

### Adaptive planning

Built — the 9-term evidence-grounded `core_utility` plus 3 opt-in
exploration terms (`docs/ARCHITECTURE.md` §6). Tested
(`test_aginiti_planner.py`, `test_target_graph.py`, `test_novelty.py`,
`test_technique_cluster_diversification.py`). **Live evidence now
includes a real, mechanistically-traced planning advantage on TWO separate
real targets**: exp20 (AnythingLLM, §0) and exp29 (`hardened_agent`, 3/3
ground-truth wins at equal budget vs. Random 2/3 and Static 1/3, `docs/
EXP29_RESULTS.md`) — this is a material update from earlier in the
project, when the only live comparative evidence (the 2026-08-07
mock-target pass) did not favor Aginiti. Getting to the exp29 result
required diagnosing and fixing two real, live-postmortem-found gaps in the
exploration terms themselves (`PROACTIVE_COVERAGE_BONUS` — no reward for a
genuinely untried FAMILY unless a sibling already looked dead; `technique_
cluster_diversification` — nothing at the finer, within-family grain where
several operators are near-duplicate wrapper variants of one hypothesis,
not independent techniques), each isolated and offline-proven (exp30,
exp31, §0) before being confirmed live. **Still unproven at the frozen
protocol's required scale:** the DVLA RQ1 benchmark has never run to
completion at a meaningful trial count, and exp29 itself is honestly
underpowered at N=3 per condition.

### Multi-step discovery (`ClassPrecondition`)

Built (`aginiti/operators/library.py`, `aginiti/graph/target_graph.py`'s
hub-node mechanism). Tested (11 dedicated tests, plus 6 more for the
hub-edge machinery, plus a 4-test cross-check via the agentic-primitives
pack). **Live/dry-run evidence:** proven offline via the 6-step discovery
chain and the agentic-primitives cross-check (§0) — both show a chain
completing through whichever of two interchangeable upstream operators
actually fires, with zero code changes elsewhere. **Unproven:** has not yet
been exercised against a live target where the discovered topology wasn't
also known in advance by the person writing the demonstration; exp20's
real chain-pivoting behavior used pre-existing exact-key `Precondition`
chains, not `ClassPrecondition` — the two capabilities are currently
proven independently, not yet proven to compound on the same live result.

### Composite scoring

Built (`aginiti/composite_score.py`). Tested (5 unit tests + the 300-trial
Monte Carlo in §0). **Live evidence:** not yet run against a live campaign
result — callable against exp16-exp20's existing trial logs, but this has
not been done and reported yet. **Unproven:** whether the "cost_efficiency
= 0 at exactly full budget" edge case (documented in `docs/
MULTI_STEP_DISCOVERY_AND_SCORING.md`) meaningfully distorts any real,
already-reported result if applied retroactively.

### Structured failure diagnosis

Built (`aginiti/graph/failure_diagnosis.py`, `failure_evidence_penalty`).
Tested (10 tests including an end-to-end ranking-order test). **Live
evidence:** retrofitted onto 4 real, already-live-validated operators as
pure metadata (no new behavioral claim, so no re-validation needed) — the
mechanism itself has not yet been exercised in a live campaign where a
confirmed block actually demoted a later candidate in real time.

### Ground-truth validation

Built (`BaseAdapter.ground_truth_mission_achieved()`, independent per
adapter). Tested (`test_dvla_adapter.py`, `test_dvaa_adapter.py`,
`test_mcp_stdio_adapter.py`, `test_anythingllm_adapter.py`). Live evidence
across all five targets, including a caught-before-live-run bug (the DVAA
consensus adapter's ground truth originally checked only simulator-only
text markers the real standalone server never emits) and exp20's
independent listener-log cross-check (0/3 mismatches on Aginiti's 3 real
wins). **Unproven:** ground-truth checks have never been adversarially
tested for false positives.

### Cross-protocol reasoning

Built — `CATEGORY_TRUST_EDGE` defined once, reused across the mock
library's Slack/GitHub trust probes, DVAA's A2A identity-spoofing operator,
and DVAA's consensus voter-identity trust operator, all queryable through
the identical `trust_assumptions()` function with zero protocol-specific
branching. **What this proves:** the *taxonomy* generalizes. **What it does
NOT prove:** the graph doesn't *notice* this pattern automatically — a
human still chooses to reuse the tag at operator-authoring time every time.
Roadmap Phase 2/5, not built.

### Deterministic extraction

Built (`Operator.extractor`). Tested (7 tests on the branching logic, plus
per-target extractor tests). Live — zero LLM judge calls confirmed on MCP
tool discovery, all filesystem-server operators, all 3 consensus operators.
**Unproven:** no head-to-head has measured deterministic extraction's
actual token/latency savings at scale against the judge path on identical
evidence beyond Experiment 2's n=7.

### Exception safety / architectural robustness

Built — `ObservationAdapter._send()`'s exception backstop, found necessary
by an independent, from-scratch engineering audit (`docs/
ENGINEERING_HARDENING_PASS.md`) that explicitly did not trust "500+ tests
pass" as proof of a sound architecture. Tested — 10-scenario deterministic
end-to-end suite (`tests/test_e2e_scenarios.py`), 17 targeted regression
tests. **Live evidence:** a live smoke test against the real hardened
AnythingLLM gateway post-fix — both the judge path and the deterministic-
extractor path (including a real 2-step chain's precondition gate) ran
cleanly end-to-end. **Explicitly not a benchmark** (n=1 each) — proves the
pipeline works post-fix, makes no attack-success-rate claim.

---

## 2. Targets evaluated

### DVLA (`WithSecureLabs/damn-vulnerable-llm-agent`)

3 operators, rebuilt on current LangChain (`create_agent`). Both direct
override and argument-injection attacks were **refused** — an explicitly
reported negative result (a defense holding), not a gap in the operator
library. Limitations stated in the generated profile: only one user role
tested, no delegated-authority testing.

### DVAA (`opena2a-org/damn-vulnerable-ai-agent`)

Evaluated across four surfaces. **Memory:** cross-session persistence of a
planted instruction confirmed. **A2A:** unrecognized senders correctly
rejected by default; a self-reported, unverified identity claim is trusted
and shown to grant unauthorized access — the first live proof of
`CATEGORY_TRUST_EDGE` generalizing beyond the mock target. **MCP:** a
privileged tool (shell execution) ran with no authentication or
authorization check. **Consensus/voting** (standalone server, separate from
the main fleet): all 3 operators succeeded in 3 prompts — vote deduplication
REFUTED, voter-identity trust CONFIRMED, single-identity outcome
manipulation CONFIRMED, ground truth verified independently. The full
hypothesis lifecycle (form → test → ACCEPTED, confidence 0.80) proven live
here, the only place it has been. Explicitly investigated and **not
pursued:** RAGBot's declared retrieval-poisoning vulnerability (returns
`content: null` — declared but unimplemented in the simulator) and DVAA's
real-LLM backend mode (no Groq support, no paid OpenAI/Anthropic keys).

### Official MCP filesystem reference server (`@modelcontextprotocol/server-filesystem`)

4 operators, first adapter to speak real MCP stdio transport with a genuine
`initialize` handshake. Both a relative `../` traversal and a direct
absolute path outside the declared root were correctly REJECTED — a
genuinely different result from every other target: "confirmed a real
defense actually holds," not "found a vulnerability."

### AnythingLLM (real, production-shaped RAG/agent platform)

The project's primary live target since exp11. Four real multi-step
exfiltration chains (RAG document-poisoning, automatic-mode tool
exfiltration, markdown-image exfiltration, multi-tool composition — full
table in `docs/AGINITI_OVERVIEW.md` §7), tested against a self-built
hardened gateway across two hardening rounds (`docs/HARDENED_TARGET.md`).
A 150-trial planner benchmark (exp20, §0) is the project's sharpest current
evidence of a real planning advantage. A real head-to-head against garak
(exp19) ran on the identical target. **Limitations:** all evidence is
against one AnythingLLM instance, evaluated with Gemini as the target-side
model — nothing here speaks to generalization to a different underlying
LLM or a different RAG/agent platform.

### `hardened_agent` / `healthcare_agent` (real RAG targets, added 2026-08-14)

_Missing from this section entirely until 2026-08-14, despite being the
targets `exp23`/`exp25`/`exp26` actually ran against — a real documentation
gap, not a claim these targets were untested._ Both vendored from this
repo's own `main` branch — real RAG chatbots over real document corpora
(CUAD contracts + CFPB complaints; HealthCareMagic-1k), not synthetic
fixtures; `hardened_agent` additionally has real RBAC (legal/support/ops),
chunked retrieval, output redaction, rate limiting, and conversation
memory.

**RBAC boundary: held against direct social-engineering, but WAS crossed
twice via the `ops` aggregation mechanism specifically — `exp29`
(2026-08-14) is the update to the "never crossed" finding reported
through `exp23`/`exp25`/`exp26`.** Reading the target's actual source
(`personas.py`/`agent.py`) confirms retrieval is scoped via a ChromaDB
`where` filter applied INSIDE the vector search (pre-filter, in the
Pinecone-documented sense — see `docs/RESEARCH_AND_PROVENANCE.md`), and
`persona` is derived only from the authenticated bearer key with no
client-supplied override anywhere in the request schema — this remains
correct and explains why the 5 `hardened_authority_claim_probe_*`
variants and `hardened_cross_boundary_probe` never once produced an
independent finding across any of exp23/25/26/28/29's live trials, on any
persona. What changed: `exp29`'s independent-oracle-only findings audit
(`docs/EXP29_RESULTS.md`) found the `ops` persona's own `hardened_ops_
aggregation_probe_1`/`_2` operators DID twice retrieve real CUAD/CFPB
records never flagged `ops_visible` for that persona's declared
(sub-domain) scope — a genuine `L3_privilege_boundary` crossing,
independently verified (fuzzy corpus match + the record's own `ops_
visible` metadata), not an LLM-judge opinion. The pre-filter architecture
correctly blocks retrieval from returning content OUTSIDE a persona's
declared source set (`cuad` for legal, `cfpb` for support) — it does not,
on this evidence, correctly restrict `ops`'s own AGGREGATE view to only
the subset of in-source records specifically flagged for cross-department
use. A real, narrower, more precise finding than "RBAC never crossed" —
and 8 further RAG/generation-guardrail over-disclosure findings (in-
domain content surfacing via generic follow-ups, indirect reframes, or
encoding tricks more readily than a properly-scoped answer should allow)
that are NOT RBAC issues. Full findings-by-finding audit in `docs/
EXP29_RESULTS.md`.

**Two real judge/oracle bugs found live and fixed, not just hypothesized**:
(1) the LLM judge misclassified an explicit refusal (the target decoding
and quoting back an embedded instruction, then declining it) as compliance
on more than one live trial — fixed with BOTH a tightened judge prompt AND
a structural `_corroborated()` gate requiring the target's own independent
ground truth to agree before any phase is allowed to stop the assessment
early (`aginiti/assessment.py`) — the corroboration gate has since been
live-confirmed catching exactly this pattern in real time (`exp26_run.log`).
(2) The fuzzy-disclosure oracle was miscalibrated against this specific
corpus's formulaic legal/regulatory boilerplate (SEC redaction disclaimers,
FCRA citations) recurring across many documents and being counted as
disclosure evidence regardless of actual relevance — fixed with a document-
frequency (TF-IDF-style) rarity filter.

**Genuinely new capability, not just a bugfix**: `aginiti/adaptive/
membership_inference.py` (the Interrogation Attack) — live-verified
against `hardened_agent`, a real ingested document scored 1.0 (4/4 correct
answers) — but the mechanism's real signal is fragile to conversation
state, live-demonstrated the hard way: appended after ~60 prior probing
turns on the same persona (`exp26`), all 6 member/non-member checks
collapsed to an identical, information-free -0.5 (hardened_agent's own
memory-caution system-prompt behavior applying uniform caution after a
long session). Re-run correctly (`exp27` — fresh server restart
immediately before, MI as the ONLY query each persona's key sends): a
clean, consistent separation across all 3 personas -- average gap 1.06
(legal 1.31, support 0.75, ops 1.13, the last after also fixing a real
test-candidate-selection bug of its own -- see `docs/EXP26_RESULTS.md` for
the full, honest arc of both failures and the fix). This is corpus-
membership inference WITHIN a persona's own authorized scope, not an
RBAC-boundary-crossing technique (see above for why a cross-persona
variant shows zero signal on this specific, pre-filter-correct target).

**Full experimental record and final analysis: `docs/EXP26_RESULTS.md`**
(covers `exp25`/`exp26`/`exp27` as one assessment arc) — raw data in
`runs_exp25_full_assessment_vs_baseline/`, `runs_exp26_full_assessment_v2/`,
`runs_exp27_membership_inference_fresh/`.

**A second, later chapter — `docs/EXP29_RESULTS.md`** (covers `exp28`
through `exp31`): the first live run of RQ1's own 4-condition methodology
against this target (`exp28`) surfaced two real planner gaps and two real
harness-methodology gaps (memory contamination across trials, fake
replication from a deterministic policy's repeated seed); both fixed,
each isolated and offline-proven (`exp30`/`exp31`) before the corrected
live re-run (`exp29`) — the RBAC crossings above are that re-run's own
independent-oracle-verified finding. Raw data in `runs_exp28_rq1_
hardened_agent/`, `runs_exp30_offline_planner_fix_validation/`,
`runs_exp31_offline_cluster_fix_validation/`, `runs_exp29_rq1_hardened_
agent_fresh_state/`.

### InjecAgent (Zhan et al., ACL Findings 2024)

1,054 real, vendored benchmark test cases (indirect prompt injection via
tool output), driven through Aginiti's own adapter/campaign loop rather
than the paper's own evaluation harness. **Not yet carried through to a
completed, externally-comparable result** — the integration needed real
structural bug fixes just to make the dataset winnable through Aginiti's
own pipeline, and no full live run against the complete pool has been
reported yet.

---

## 3. What Aginiti can currently reason about

| Dimension | Status | Evidence |
|---|---|---|
| **Identity** (claimed vs. verified) | Proven | DVAA A2A spoof, DVAA consensus voter-ID trust |
| **Memory / persistence** | Proven | DVAA cross-session memory persistence |
| **Trust** (delegated, self-reported) | Proven, cross-protocol | `CATEGORY_TRUST_EDGE` across mock/Slack, DVAA/A2A, DVAA/consensus |
| **Capabilities** (what a target exposes) | Proven | `capabilities()` populated live for all 5 real targets |
| **Tool execution** (authorized vs. not) | Proven | DVAA unauthenticated execution; AnythingLLM automatic-mode tool exfiltration |
| **Authorization** | Proven | Same as tool execution; also DVLA's override refused; `hardened_agent`'s `ops` persona twice received non-`ops_visible` content via its own aggregation probes (exp29, `docs/EXP29_RESULTS.md`) — the project's first confirmed RBAC crossing on this target |
| **Input validation** | Proven | DVLA injection refused; MCP filesystem boundary enforcement held |
| **Coordination** (multi-actor consensus) | Proven | DVAA consensus scenario, full 3-operator chain |
| **Outcome manipulation** | Proven | Single-identity consensus manipulation confirmed |
| **Multi-step chain execution** | Proven | 4 real AnythingLLM chains, up to L5, ground-truth-verified |
| **Multi-step chain discovery (not pre-wired)** | Proven, offline only | `ClassPrecondition` 6-step chain + agentic-primitives cross-check — not yet exercised on a live target |
| **Planner advantage over simpler baselines** | Proven, two real targets | exp20's chain-required-mission result on AnythingLLM; exp29's 3/3-vs-2/3-vs-1/3 result on `hardened_agent` (§0, `docs/EXP29_RESULTS.md`) |
| **Planning / delegation depth** (multi-agent orchestration beyond A2A) | Not evaluated | No target integrated exercises this |
| **Retrieval / RAG poisoning** | Proven | AnythingLLM's RAG-poisoning chain; DVAA's RAGBot rejected as a dead end |
| **Reasoning under adversarial context** (indirect injection via retrieved/tool content) | Proven | AnythingLLM's trigger operators; InjecAgent's 1,054 test cases (integration real, full-pool result not yet reported) |
| **Recovery after failure** | Not evaluated | No metric or operator sequence targets this |

---

## 4. Comparison against existing approaches

**Caveat, binding for the whole table:** the columns below reflect this
project's understanding of each named system's publicly documented design,
not a hands-on side-by-side evaluation in every row — where a claim about
another tool isn't independently verifiable with reasonable confidence,
it's marked **Unknown** rather than guessed. The garak row is the
exception: it is a real, run comparison (`docs/COMPETITOR_COMPARISON.md`),
not just an architectural characterization.

| Capability | Aginiti | BloodHound | Generic pentest agents | garak (real comparison run) |
|---|---|---|---|---|
| Interaction-derived graph, built from live probing | ✔ Proven, all five targets | ✖ Ingested static data | Unknown | ✖ Scored probe log, no persistent graph |
| Cross-protocol reasoning (reused abstraction) | ✔ Proven — `CATEGORY_TRUST_EDGE` across 3 protocols | ✖ Single-domain by design | Unknown | ✖ Protocol-specific probe libraries |
| Hypothesis lifecycle (form → test → resolve) | ✔ Partial — proven live once | ✖ No hypothesis concept | Unknown | ✖ No persistent belief-revision object |
| Multi-step chain execution against a real target | ✔ Proven — 4 AnythingLLM chains up to L5 | ✔ Core capability, different substrate | Unknown | ✖ REST-generator interface structurally cannot observe L2-L5 |
| Multi-step chain **discovery** (not pre-wired) | ✔ Proven offline via `ClassPrecondition` | ✔ Core capability over ingested data | Unknown | ✖ Not applicable |
| Real, live head-to-head result | 4/5 categories agree exactly with garak; the hardened target held against both | N/A | N/A | Real, run, both directions reported honestly |
| Planner advantage over simpler baselines | ✔ Proven on two real targets (exp20, exp29) | N/A — query-driven, not autonomously adaptive | Unknown | ✖ Static/enumerated by design |

---

## 5. Missing evidence

**Claim: "The planner beats simpler baselines."** Status: **proven on one
real target, one mission shape (exp20)**; **not proven at the frozen RQ1
protocol's scale** on DVLA, and the earlier mock-target pass did not show
an advantage under the pre-`chain_value` planner. Needed: (a) complete the
frozen `analysis_plan.md` RQ1 protocol against DVLA at a meaningful trial
count; (b) a larger N specifically for exp20's chain-required-mission ASR
claim, since the pairwise comparison is currently underpowered; (c) test
whether exp20's chain-pivoting advantage holds at other budget sizes.

**Claim: "`ClassPrecondition` discovery works on a live target."** Status:
**proven offline only.** Needed: a live campaign against a target with
genuinely undeclared chain topology, not a demonstration pack authored to
prove the mechanism.

**Claim: "Deterministic extraction is cheaper/faster/more reliable than the
judge."** Status: **architecturally sound, not measured at scale.** Needed:
a controlled comparison at a larger sample than Experiment 2's n=7.

**Claim: "The confidence model reflects actual correctness."** Status:
**not yet proven.** Needed: a labeled (claim, ground truth) dataset across
live runs.

**Claim: "Insight synthesis produces non-overclaiming, useful
conclusions."** Status: **not yet proven** — the prompt is engineered
against overclaiming, but no independent human rater has scored generated
insights. Needed: the long-deferred blind judge/insight validation pass
(30-50 human-labeled transcripts).

**Claim: "Hypothesis accept/reject thresholds are reasonable."** Status:
**not evaluated** — arbitrary v1 constants. Needed: a calibration
experiment or an explicit acknowledgment this stays a heuristic.

**Claim: "The category taxonomy keeps generalizing to new targets."**
Status: **partially proven** — held for 3 protocols on `CATEGORY_TRUST_EDGE`
specifically. Needed: a 6th, structurally new target.

**Claim: "The agentic-primitives pack (approval gates, untrusted tool
output) works against a real target."** Status: **not evaluated** —
dry-run only, deliberately deferred pending live DVAA validation.

**Claim: "Composite scoring changes how exp16-exp20's real results should
be read."** Status: **not evaluated** — the scorer is validated on
synthetic data (§0) but has not been applied retroactively to any real,
already-reported campaign result.

---

## 6. Benchmark roadmap

The canonical tracked list of experiments identified as needed but not yet
run, superseding any duplicate mention elsewhere:

1. **RQ1 at scale** — the frozen DVLA protocol, completed 4-condition run
   at the pre-registered effect-size bar.
2. **exp20's chain-required mission at a larger N**, specifically to move
   the pairwise Aginiti-vs-baseline comparison past p=0.224.
3. **`ClassPrecondition` on a live target** with genuinely undeclared chain
   topology.
4. **The agentic-primitives pack against a live target** (DVAA, most
   likely) — the one deliberately deferred piece of the multi-step-
   discovery chapter.
5. **Composite scoring applied retroactively** to exp16-exp20's existing
   trial logs, to see whether it changes which result reads as the
   strongest.
6. **Deterministic extraction vs. judge**, head-to-head at a larger sample.
7. **Blind judge/insight validation**, 30-50 human-labeled transcripts —
   the longest-standing deferred task in the project.
8. **Recovery-after-failure and branch-efficiency metrics** — no metric
   exists yet.
9. **Graph quality** — no defined metric independent of downstream campaign
   success.
10. **Hypothesis quality/threshold calibration**, and whether a REJECTED
    hypothesis is ever correctly rejected (only ACCEPTED observed live).
11. **A 6th target** to test continued category-taxonomy generalization.
12. **A full InjecAgent-pool live run**, carried through to a completed,
    externally-comparable result.

A roadmap phase in `docs/ROADMAP.md` is only marked "current" if at least
one experiment above is actively being worked, and "complete" only once its
corresponding experiment(s) have run and the result is recorded back here.

## 7. Known methodology limitations

Surfaced by internal + external audits at two points in the project's
history — recorded here rather than fixed in code because each one is a
genuine scope/methodology limitation, not a bug.

**From the 2026-08-09 audit of the AnythingLLM planner benchmarks
(exp12-15):**

1. **Partial circularity in `branching_chat_rag`'s "known trap."**
   `memory_context_leakage_probe` is labeled a trap specifically because
   this project's own earlier sessions established it's reliably defended
   against this exact target instance — a legitimate test of the
   *mechanism* (can a short target description reproduce a real prior), but
   closer to "did we re-derive our own prior knowledge" than "did we
   correctly reason about a genuinely novel target."
2. **Budget-vs-candidate-count structural insensitivity** in the same
   mission — a losing trial always tries all 3 candidates regardless of
   pick order, so pick *quality* shows up in efficiency (prompts-to-
   success, confirmed significant, p<0.005) but not in the success-rate
   comparison the benchmark's own headline numbers report.
3. **Single target, single mission family, single underlying model** across
   all of exp12-16 — nothing there speaks to generalization to a different
   target, mission topology, or LLM.
4. **No comparison against any external tool existed at that point** — this
   specific gap is now closed by exp19's real garak comparison, but every
   *other* comparison in the project's history remains against baselines
   this project wrote itself.

**From the 2026-08-12 independent engineering-hardening audit** (`docs/
ENGINEERING_HARDENING_PASS.md`, full detail there):

5. **No single, unified benchmark harness.** Three parallel execution paths
   exist (`run_campaign`, `run_understanding_loop`, and per-experiment
   bespoke scripts) — a fix to one doesn't automatically propagate to the
   others except where it lives in the shared `ObservationAdapter`.
6. **Not every adapter is equally hardened.** AnythingLLM has adapter-
   specific failure classification; DVAA and MCP-stdio rely solely on the
   generic exception backstop added during this audit.
7. **`aginiti/adaptive/*` is architecturally disconnected from
   `AginitiPlanner`** — real, tested, has produced real live results (the
   exp20 discovery-arm test), but is never ranked alongside static
   operators in the same planning decision.
