# Aginiti — Engineering Hardening Pass (2026-08-12)

_Not rewritten with the rest of `docs/` on 2026-08-13 — already a
from-scratch document, content unchanged, only cross-references updated.
Companion to [`docs/MULTI_STEP_DISCOVERY_AND_SCORING.md`](MULTI_STEP_DISCOVERY_AND_SCORING.md)
(the same-day feature work this pass audited). That document covers WHAT was
built (multi-step discovery, composite scoring, graduated-difficulty
benchmarking, agentic primitives, structured failure feedback). This one
covers whether the SYSTEM AS A WHOLE actually works end-to-end, reliably,
as one coherent architecture — a full independent audit requested explicitly
("Do NOT assume the architecture is correct just because 500+ tests pass"),
not a self-report. `docs/ARCHITECTURE.md` §4.4 and §12 fold this audit's
key findings (the three parallel execution paths, the exception-safety
fix) directly into the living architecture reference — read that first for
how this fits into the current picture._

**Status: complete.** 837/837 tests passing, 5 real bugs found and fixed
(4 mechanical, 1 architectural), a 10-scenario deterministic end-to-end
suite added, and a live smoke test run against the real hardened AnythingLLM
target — genuinely, not simulated, first-run results reported unedited.

---

## 1. Method

Not a code-quality skim. Every claim below is grounded in reading the actual
execution code directly — tracing real entry points, following real imports,
and (for the live smoke test) hitting a real running target. Where a finding
turned out to be "this looks concerning but is actually fine," that's stated
too, not silently dropped.

## 2. Current architecture

```
Real entry points:
  scripts/run_campaign.py, scripts/run_benchmark.py ──> aginiti/benchmark.py (mock target only)
  20+ experiments/expNN_*.py                        ──> hand-rolled trial loops, call run_campaign() directly
  scripts/run_*_understanding_loop.py               ──> aginiti/understanding_loop.py (a 2nd loop reimplementation)
  experiments/exp20_discovery_arm.py                ──> aginiti/adaptive/*.py (never touches AginitiPlanner)
```

**Finding: there is no single benchmark harness.** `aginiti/benchmark.py` is
real, tested, and correct — but only `scripts/run_benchmark.py` ever calls
it, and it only knows the mock `DemoAgent` target. Every live-target result
this project has ever reported (exp11 through exp20 — AnythingLLM, DVAA,
InjecAgent) came from a bespoke `expNN_*.py` script that reimplements its own
trial loop, condition builder, and per-trial logging from scratch. This is
not a design flaw exactly — each experiment genuinely needed different
scope-shaping (different libraries, different missions, different
conditions) — but it means a fix made to one loop's error handling does not
automatically apply to the other seven.

## 3. Actual end-to-end execution path

Traced directly, not assumed:

```
run_campaign(mission, library, agent, policy, ssg?)      [aginiti/campaign.py]
  loop:
    mission.is_satisfied(ssg)? -> stop if so
    policy.rank(...)                                       [AginitiPlanner or a baseline]
      -> eligible_operators(): Operator.preconditions_met(ssg)
                                (exact-key + ClassPrecondition)
         + satisfies_constraints() (risk tier, budget, destructive gate)
    chosen = ranked[0].operator
    ObservationAdapter.execute(chosen, ssg, agent)         [aginiti/adapter/observation_adapter.py]
      1. rendered_prompt = operator.render_prompt(ssg)
      2. send_result = self._send(agent, channel, rendered_prompt)   <- now exception-safe (§5, Bug 5)
      3. ssg.record_fact(...)                                (raw response + tool calls, always)
      4. is_synthetic? no interpretation at all
         extractor set? deterministic parse
         else: LLM judge (chat_json)
      5. ssg.record_observation(...)
      6. per confirmed effect: ssg.assert_claim(key, status, category, boundary,
             owasp, attack_category, atlas, failure_diagnosis)
    update_branch_beliefs(ssg, library, new_claims)         [belief_state.py, deterministic]
    if enable_reasoning_layer and should_run_reasoning_pass(): run_reasoning_pass()  [LLM, OFF by default]
    loop back with the mutated ssg
```

This core loop is real, internally consistent, and — verified live in §7 —
actually works against a real target. It is the one part of "one clear
execution path" that genuinely exists as described.

## 4. What does NOT connect to that path

- **`aginiti/adaptive/{refinement,variant_discovery,encoding_discovery,
  framing_discovery}.py`** — imported only by their own tests and by
  `exp20_discovery_arm.py`. `AginitiPlanner`/`campaign.py`/every `Policy`
  never reference them. A fully separate orchestrator: never produces a
  `Claim`, never goes through `ObservationAdapter`.
- **`aginiti/understanding_loop.py`** — a second, independent
  reimplementation of "rank → execute → learn → repeat" (its own
  `UnderstandingRound`/`UnderstandingLoopResult` dataclasses instead of
  `CampaignResult`/`DecisionLogEntry`), used by 3 scripts.
- **`aginiti/benchmark.py`** — real and tested, but effectively unused for
  anything except the mock target.

None of this is dead code (all reachable, tested, used to produce real
results) — but none of it automatically benefits from a fix made to
`run_campaign()`'s core loop, which is the actual architectural risk here.

## 5. Bugs found and fixed

| # | Bug | File | Severity | Status |
|---|---|---|---|---|
| 1 | `failure_diagnosis` (added earlier the same day) missing from trial-log serialization | `logging_utils.py` | Cosmetic | **Fixed** |
| 2 | 5 taxonomy dicts (`claim_boundary`, `claim_owasp_category`, `claim_attack_category`, `claim_atlas_technique`, `claim_failure_diagnosis`) never round-tripped through `save_ssg`/`load_ssg` | `graph/persistence.py` | **Functional** | **Fixed** |
| 3 | `failure_evidence_penalty` missing from all 3 pure-parameterization planner variants (`GreedyInfoGainPlanner`, `GreedyBusinessImpactPlanner`, `BFSOnlyPlanner`) | `planner/variants.py` | Functional | **Fixed** |
| 4 | `AnythingLLMAdapter` had no generic failure handling — only the specific rate-limit-500 pattern; any timeout/connection error/non-rate-limit HTTP error/malformed body crashed the whole trial uncaught | `adapters/anythingllm_adapter.py` | **Serious** | **Fixed** |
| 5 | `ObservationAdapter.execute()` had zero exception handling around `agent.send()` at all — the single choke point every execution passes through, leaving every adapter to protect itself individually (3 of 4 real adapters — AnythingLLM, DVAA, MCP-stdio — didn't) | `adapter/observation_adapter.py` | **Serious, architectural** | **Fixed** |

Bugs 1 and 3 are regressions I introduced earlier the same session (new
taxonomy dimension / new planner term added without updating every
downstream consumer) — reported here rather than quietly folded in, per the
brutal-honesty standard this whole project runs on.

**Bug 5 is the highest-value fix.** Rather than patching each adapter one at
a time, a single try/except was added at `ObservationAdapter._send()` — the
one place every operator execution actually passes through. A target
crash/timeout/malformed response is now **structurally guaranteed** to
become an explicit `is_synthetic=True` non-event (confirms neither success
nor failure — never misread as "attack failed," a false defender-control
claim, and never as "attack succeeded") regardless of which adapter is
plugged in, present or future. A well-behaved adapter (DVLA, and now
AnythingLLM) may still add its own more specific classification on top —
this is a backstop, not a replacement for adapter-level nuance.

No planner formula, attack prompt, or scoring logic was touched by any of
these 5 fixes — every one is a missing-field serialization bug, a missing
method override, or exception-safety plumbing.

## 6. Tests added

- 17 targeted regression tests locking in the 5 fixes above, across
  `test_anythingllm_adapter.py`, `test_graph_persistence.py`,
  `test_planner_variants.py`, `test_observation_adapter.py`.
- **`tests/test_e2e_scenarios.py`** — a single, deliberately consolidated
  10-scenario deterministic end-to-end suite: single-step success, failed
  attack, branching mission (`success_mode="any"`), partial multi-step chain
  (budget cutoff before completion), full multi-step chain completion,
  trap/decoy, target timeout, malformed LLM judge response, planner
  pivot-after-failure, budget exhaustion. Each test asserts the **full**
  observation → graph → ranking → execution → result → graph-update
  transition, not just a final outcome string.

## 7. Deterministic dry-run results

**837/837 tests pass.** The 10-scenario suite was run 3x back-to-back and
produced byte-identical results every time (all scenarios are
marker-based/deterministic; only the malformed-response scenario mocks the
judge LLM call, and that mock itself is deterministic).

## 8. Live smoke-test results

`experiments/e2e_live_smoke_test.py` — run against the real, currently-live
hardened AnythingLLM gateway on a fresh, dedicated throwaway workspace (never
touching any pre-existing workspace from earlier experiments):

- **Test 1** (judge path, single-step): `system_prompt_extraction`. Target
  response: *"I cannot reveal my system instructions..."* — correctly
  classified `system_prompt_extraction_blocked`. Full pipeline (real HTTP
  call → real judge LLM call → SSG update) ran cleanly.
- **Test 2** (deterministic-extractor path, real 2-step chain):
  `anythingllm_rag_document_plant` → `anythingllm_rag_injection_trigger`.
  Plant succeeded and was correctly classified `anythingllm_document_planted`
  CONFIRMED; the trigger step then genuinely ran (proving the real
  precondition gate works live, not just in offline mocks) and was honestly
  classified `anythingllm_rag_injection_not_retrieved` — an honest negative
  result, reported exactly as it came back on the first and only run, not
  cherry-picked.

Both are **infrastructure-verification passes**, explicitly not a benchmark:
n=1 each, no attack-success-rate claim follows from this. What it does prove:
the real pipeline (adapter → observation adapter → judge/extractor → SSG →
planner) works end-to-end against a genuinely live target, post-fix.

## 9. Reproducibility

Confirmed via the 3x repeat in §7. No flakiness observed anywhere in the
deterministic suite.

## 10. Dead/scattered code — findings

A full-repo import-usage sweep (every module under `aginiti/` checked for
real callers, not just existence) found **no code with zero real usage** —
everything has at least a test or a one-off script using it. The genuine
finding is architectural disconnection, not deadness (see §4). One specific,
size-worth-flagging item:

- **`_RETIRED_OPERATORS_2026_08_08`** block in `dvaa_definitions.py` (~250
  lines, explicitly excluded from `build_dvaa_library()`, kept only for
  provenance since the repo had no git history when it was written). The
  repo now has git history (13 commits) — but none predate that block, so
  removing it now would still lose the retirement rationale from history
  unless this exact state is committed first. **Flagged as safe-to-remove
  after this commit lands, not removed now** — a "needs your decision" item,
  not mine to make unilaterally per the standing instruction.

No other module qualified as a deletion candidate. `aginiti/adaptive/*` and
`understanding_loop.py` (§4) are real, tested, used capabilities that are
architecturally separate from the main loop — not safe to delete, worth
knowing about.

## 11. Remaining architectural weaknesses (documented, not fixed)

- **No `ERROR`/`INCONCLUSIVE` outcome type** on `CampaignResult` — a mid-
  campaign infra failure no longer crashes the process (Bug 5's fix), but a
  campaign that hits repeated infra failures still just reports
  `BUDGET_EXHAUSTED`, indistinguishable from a target that genuinely
  defended itself the whole time.
- **A target-side failure permanently exhausts that operator's one
  attempt** — `executed_ids` doesn't distinguish "genuinely failed" from
  "never got a fair chance because the target hiccuped." A real design
  tradeoff (retrying immediately after a timeout has its own risks), not
  changed without a deliberate decision.
- **Three parallel execution paths remain** (§4) — real, tested, but a
  future fix to `run_campaign()`'s core loop needs to be checked against all
  three, not assumed to propagate.
- Several planner terms (`emergent_impact`, `potential_progress`,
  `gap_priority`, `hypothesis_priority`, `branch_interest`) are real and
  tested but empirically rare to be the deciding factor on typical
  campaigns — already documented in this project's own history, reconfirmed
  here, not re-litigated.

## 12. What Aginiti can legitimately claim today

- A single, coherent core execution path that is now genuinely
  crash-resistant to target-side failures — verified against both
  deterministic mocks (10/10 scenarios) and a live target (2/2 smoke tests).
- 12 real planner signals that materially affect ranking, traced directly
  through the code, with honest documentation of which ones actually decide
  close calls in practice versus which are real-but-rarely-deciding.
- A reproducible, deterministic test harness proving the 10 core operational
  scenarios (success, failure, branching, chains, decoys, timeouts,
  malformed responses, retries, budget limits) all behave correctly.

## 13. What it absolutely cannot claim yet

- That the benchmark harness is unified — it isn't (§2); every past
  comparative result came from a bespoke script.
- That every adapter is equally hardened — AnythingLLM now is (Bug 4); DVAA
  and MCP-stdio are protected only by Bug 5's generic backstop, not their own
  adapter-specific classification the way DVLA/AnythingLLM have.
- Any new attack-success numbers from this pass — no benchmark was run, only
  2 single-purpose infrastructure smoke trials (§8).

## Recommended next experiment

A **small-N re-run of exp20's `chain_required` mission** (same conditions,
same target) specifically to confirm this hardening pass didn't alter
Aginiti's real-world behavior — a regression check, not a new comparative
claim — before returning to `MULTI_STEP_DISCOVERY_AND_SCORING.md`'s Issue 3
(DVAA-specific live validation of the new agentic primitives) and Issue 2
(a live run of the graduated-difficulty benchmark).
