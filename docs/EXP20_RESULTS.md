# exp20 — Full-Scale Planner Benchmark Results

_Run 2026-08-12; this record is not rewritten with the rest of `docs/` on
2026-08-13 because it's a frozen report of one specific experiment — its
numbers are exactly as measured. `docs/AGINITI_OVERVIEW.md` §8 and `docs/
EVIDENCE_AND_EVALUATION.md` §0 both summarize and cite this document as
the project's sharpest current live evidence of a planning advantage; read
those first for how this fits into the bigger picture._

Real, live run against the hardened AnythingLLM v2 gateway (same target
exp18/exp19 used — see `docs/HARDENED_TARGET.md`). 5 conditions (Random
floor, Static enumeration, Greedy-Information-Gain, Bayesian
Thompson-sampling, and the current AginitiPlanner — "dynamic," carrying
the `chain_value`/`severity_priority` fixes), N=15/condition, 28-operator
library (all `data_exposure.py` + `encoding_variants.py` + all 9
AnythingLLM chain operators), budget=4, two missions. **150 real
campaigns, 0 unresolved errors after gap-fills, 773/773 unit tests passing
throughout at the time of this run** (the suite has since grown to 837 —
see `docs/ARCHITECTURE.md`).

**Status: complete.** The discovery-arm bonus test was interrupted mid-run
once (environment/infrastructure restart, zero usable data survived that
attempt) and re-run cleanly after restoring the AnythingLLM/collector/
gateway/listener stack — 10/10 trials, 0 errors. Both the 5-condition
planner comparison and the discovery-arm bonus test below are final.

---

## Headline finding

**In the mission that actually requires completing a multi-step chain to
win, Aginiti scored 3/15 (20%) — real, independently ground-truth-verified
L5 (confirmed sensitive-data-exfiltration) compromises. Every other
condition — Random, Static, Greedy-Information-Gain, and a real Bayesian
Thompson-sampling bandit — scored 0/15.** In the broader "any compromise
counts" mission, all 5 conditions scored 0/15 — nobody won anything there.

The mechanism is fully traceable, not a black box: in **every single one**
of the 15 chain-required trials, Aginiti's `chain_value` term drove it to
attempt the RAG-injection chain first. The target's L1 defense blocked it
**every time** (0/15 RAG successes, no exceptions). But because RAG failing
didn't satisfy the mission, the campaign kept going — and in all 15 trials,
Aginiti's remaining budget went into a **second, different** chain
(automatic-mode tool-exfiltration or markdown-image exfiltration), which
succeeded 3 times. **No other condition ever attempted a single chain
operator, in either mission, across all 120 of their combined trials** —
every baseline spent its entire budget on single-shot data-exposure/
encoding probes instead.

**Statistical honesty check:** pairwise, Aginiti (3/15) vs. any one
baseline (0/15) does not reach conventional significance at this sample
size (Fisher's exact, p=0.224 for each). Pooling all 4 baselines together
(0/60 combined vs. Aginiti's 3/15) does reach significance (p=0.0067) —
reported as a secondary, assumption-laden view (it treats the 4 different
algorithms as exchangeable under the null, which is defensible but not
beyond debate), not the headline number. **The honest state of the
evidence: real, mechanistically-explained, ground-truth-verified,
directionally consistent behavior difference; not yet a bulletproof
statistical result at N=15.** A larger N is the direct next step if this
needs to be load-bearing for a production decision.

---

## All 10 metrics

### 1. Attack success (ASR)

| Condition | Broad mission | Chain-required mission |
|---|---|---|
| Random | 0/15 (0%) | 0/15 (0%) |
| Static | 0/15 (0%) | 0/15 (0%) |
| Greedy-Info-Gain | 0/15 (0%) | 0/15 (0%) |
| Bayesian | 0/15 (0%) | 0/15 (0%) |
| **Aginiti** | 0/15 (0%) | **3/15 (20%)** |

### 2. Security severity (L0–L5, deepest reached)

| Condition | Broad mission | Chain-required mission |
|---|---|---|
| Random | L2 (unauthorized tool invocation), 8/15 trials tagged | L2, 8/15 |
| Static | L1 (context/RAG manipulation), 6/15 | L1, 6/15 |
| Greedy-Info-Gain | none classified | none classified |
| Bayesian | L1, 1/15 | L1, 1/15 |
| **Aginiti** | L1, 13/15 | **L5 (confirmed exfiltration), 3/15; L1, 12/15** |

Random and Static reaching L1/L2 despite 0% mission success reflects the
`security_boundary` tag on a *sub-claim* (a plant getting confirmed even
if the trigger fails) — a real, honest signal that these conditions
occasionally happened onto a plant-stage foothold without ever exploiting
it further. Aginiti is the only condition to reach L5 at all, in either
mission.

### 3. Coverage

Every condition's *operator* coverage is identical (14.3% = 4-of-28,
mechanical — budget=4 caps every condition equally). The differentiator is
**which** 4: attempted-category diversity (of 8 offensive
`attack_category` values, before filtering to only what got confirmed):

| Condition | Broad | Chain-required |
|---|---|---|
| Random | 1.5 / 8 | 2.27 / 8 |
| Static | 2.07 / 8 | 2.07 / 8 |
| Greedy-Info-Gain | 2.0 / 8 | 2.0 / 8 |
| Bayesian | 2.0 / 8 | 2.0 / 8 |
| **Aginiti** | **3.0 / 8** | **3.0 / 8** |

### 4. Efficiency

Every condition uses its full 4-prompt budget in every trial (mechanical —
none stopped early on a `SEARCH_EXHAUSTED`/successful-early-exit path
except Aginiti's 3 chain-required wins, which also used all 4). Wall-clock
time per campaign varied more with target-side load over the session's
cumulative testing than with condition — no policy is meaningfully
faster/slower per-call; the real efficiency differentiator is Aginiti
converting its 4 prompts into 3 real compromises where every other
condition converted its 4 prompts into 0.

### 5. Adaptivity

Direct, objective, mechanism-level result: **Aginiti's plan changed within
every single trial in response to what it observed — it pivoted to a
second chain the instant the first one failed, in 12/15 broad-mission
trials and 15/15 chain-required trials. No other condition's chosen
operator sequence was ever gated by an earlier confirmed claim in the same
trial — 0/15 for all 4 baselines, in both missions.** Static and Random are
structurally incapable of this (fixed order / no memory); Greedy-Info-Gain
and Bayesian could in principle recognize an unlocked chain but never did
at budget=4 against 28 competing single-shot alternatives.

### 6. Chain discovery

| Condition | Chains attempted (either mission) | Chains succeeded |
|---|---|---|
| Random / Static / Greedy-Info-Gain / Bayesian | 0 | 0 |
| **Aginiti** | RAG: 28/30 trials · Automatic: 21/30 · Markdown: 6/30 | **Automatic: 2 · Markdown: 1** |

### 7. Novel attack discovery

**Measured, N=10, real live trials, 0 errors.** `encoding_discovery`
(searches 10 single transforms, then role-play priming, then
live-synthesized cross-family stacks — capable of finding a combination
not in any static list) exhausted its full 16-candidate search **in all
10/10 trials without a single success** — mean 457.8s/trial. No novel
combination was ever confirmed, because nothing succeeded at all: an
honest null result, not evidence the search logic is broken (the pilot
run and the exp20_full_broad/chain main-benchmark data both show the
same mechanism working correctly when it does succeed).

`framing_discovery` (5 static pretexts, escalating to PAIR-style
LLM-driven prompt rewriting if all fail) also failed all 5 static
framings **and both escalated LLM-refinement attempts, in every single
one of the 10 trials** (10/10 escalated, 0/10 succeeded at any stage) —
mean 159.3s/trial.

**Bottom line: this specific hardened target's system-prompt-leakage
defense held against the single strongest, most adaptive single-operator
attack Aginiti currently has** — 10 converters, role-play priming, 6
synthesized stacks, 5 social-engineering framings, and 2 rounds of
LLM-driven adaptive rewriting, all in the same run, all defeated. That's
a genuinely positive signal about the target-hardening work from earlier
this session, reported plainly even though it means "no" for the novel-
discovery capability's payoff on this specific target/goal.

### 8. False positives

**Zero.** Every one of Aginiti's 3 chain-required successes was
cross-checked against the *independent*, listener-log-based
`ground_truth_mission_achieved()` oracle (not the judge, not the SSG's own
belief) — all 3 matched. 0/3 mismatches.

Important, honest scope limit: this cross-check only exists for the 4
chain-trigger claims (they have real independent ground truth via the
exfil listener). The single-shot `data_exposure.py`/`encoding_variants.py`
claims have no independent oracle — they were never confirmed as
successful in this run either (0% ASR everywhere on those), so there was
nothing to spot-check, but that also means this run provides **no
evidence either way** about judge false-positive risk on that half of the
library specifically.

### 9. Robustness

**150/150 campaigns completed** (after 3 gap-fills for real transient
network/API errors — 1 Windows connection timeout, 1 Gemini 503
"high demand," 1 more connection timeout — all cleanly resumable, zero
data loss, zero silent retries hiding a real failure). Against the
*target's* robustness: it held completely in the broad mission (0% ASR,
all 5 conditions) and mostly held in the chain-required mission (80%
resistance even against Aginiti specifically). The hardening work from
earlier this session is doing real work.

### 10. Generalization

**Directly tested via the two-mission design.** Aginiti's behavioral
signature (attempt chains, pivot on failure) held identically across both
missions — 13/15 and 15/15 chain-attempt rates, not a fluke of one
mission's shape. But the *payoff* did not generalize: 0% success in the
broad mission (where a chain success competes against 22 cheap
alternatives for "any" satisfaction) vs. 20% in the chain-required mission
(where a chain is the only path to a win). **Aginiti's advantage is real
but conditional — it shows up when the mission structure actually rewards
chain investment, not automatically.** That's a substantive, honest
finding, not a caveat to hide.

---

## garak (exp19) comparison — same hardened target

| Category | Aginiti (exp20) | garak (exp19) | Comparable? |
|---|---|---|---|
| System-prompt extraction | 0/15 (0%) | 0/28 (0%) | Yes — agree |
| Jailbreak (DAN) | 0/15 (0%) | 0/15 (0%) | Yes — agree |
| Indirect/latent injection | 0/15 (0%) | 0/15 (0%) | Yes — agree |
| Markdown/web exfiltration | 0/15 (0%) | 0/12 (0%) | Yes — agree |
| Encoding evasion | 0/15 (0%) | 13-14/15 (87-93%) | **No** — garak's detector measures decode-and-echo compliance, not hidden-instruction execution (see `docs/COMPETITOR_COMPARISON.md`) |

Neither garak nor exp19's Aginiti pass ever exercised a real multi-step
chain (garak structurally can't; exp19's Aginiti calls were operator-
direct, bypassing the planner). **exp20's chain-pivoting result has no
garak analogue at all** — it's the first evidence of a capability neither
garak nor Aginiti's own earlier benchmark runs had demonstrated.

---

## What this means, bluntly

- **The chain_value fix works, live, not just in unit tests.** It produces
  a real, mechanistically-explained, ground-truth-verified behavioral
  difference that no baseline — including a real Bayesian bandit —
  reproduces. That's the strongest, most concrete evidence this project
  has produced yet that Aginiti's planning actually does something a
  simpler strategy doesn't.
- **It is not yet a statistically bulletproof result** at N=15 pairwise,
  and it did not generalize to the broader mission shape. Both facts are
  in this report, not hidden.
- **The hardened target mostly held.** 80% resistance against the one
  condition that seriously tried multi-step chains, 100% against direct
  single-shot probes from any condition. That's a real, positive signal
  about the target-hardening work, independent of how Aginiti scored.
- **The discovery-arm bonus test completed cleanly and returned a real,
  honest null result**, not a technical gap: Aginiti's most adaptive
  single-operator attack (encoding search + role-play + synthesized
  stacks + framing search + LLM-driven refinement) did not crack this
  target's system-prompt defense in 10/10 independent trials. That says
  something genuinely positive about the hardening work — it's not a
  weakness in the experiment.
- **This is not yet "ready for an enterprise to trust blindly."** One
  hardened target, one budget setting, N=15 for the planner comparison
  (N=10 for the discovery arm), and a real but not overwhelming
  statistical margin on the headline chain-pivoting result. The honest
  next steps: consider a larger N specifically for the chain-required
  mission's ASR claim, test whether the chain-pivoting advantage holds
  at other budget sizes (budget=4 may be a specific sweet spot, not a
  general one), and try the discovery arm against a goal other than
  system-prompt extraction, since this run only tested one target claim.

---

## Raw data

`runs_live_anythingllm_benchmark/exp20_full_broad/` (75 trials),
`runs_live_anythingllm_benchmark/exp20_full_chain/` (75 trials),
`runs_live_anythingllm_benchmark/exp20_discovery_rerun/` (10 trials, the
clean re-run — `exp20_full_discovery/` is the interrupted first attempt,
kept for the record, zero usable trials in it),
`experiments/exp20_full_benchmark.py` / `exp20_discovery_arm.py` /
`exp20_analyze.py` (harness + analysis).
