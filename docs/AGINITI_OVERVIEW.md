# Aginiti — What It Is, How It Works, and What It Can Actually Do

_Last rewritten 2026-08-13. This is the project's front door: read this
first. `docs/ARCHITECTURE.md` goes deep on the codebase itself; `docs/
EVIDENCE_AND_EVALUATION.md` is the full evidence ledger with citations for
every claim below; `docs/ROADMAP.md` covers trajectory and what's next._

---

## 1. What Aginiti is

Aginiti is an **AI agent security assessment tool**: it drives a real
target (a chatbot, a RAG-backed assistant, a tool-calling agent, a
multi-agent fleet) through a live conversation, accumulates everything it
learns into a persistent, evidence-linked graph, and uses that graph to
decide what to try next — instead of firing a fixed list of payloads and
scoring pass/fail.

It exists to answer a question neither of the two dominant approaches
answers well:

- **Static probe scanners** (garak, PyRIT-style systematic probing) are
  broad and repeatable, but stateless — every probe is independent, none
  of them build on what a previous one revealed, and there's no model of
  *this specific deployment's* tools, trust relationships, or defenses.
- **Manual red-teaming** builds exactly that kind of target-specific
  understanding, but requires a human operator who already knows how to
  read the target and craft a chain by hand — it doesn't scale and doesn't
  leave behind a structured, queryable record.

Aginiti's bet: treat this as **planning under uncertainty over an evidence
graph**, not scripted enumeration. A claim about the target (`"the agent
trusts a self-reported identity"`, `"a planted document survives retrieval
and gets acted on"`) is asserted with a confidence level, gets revised as
more evidence arrives, and directly changes what the planner tries next.

## 2. How it works

```
Mission + OperatorLibrary + SecurityStateGraph + Policy/Planner + BaseAdapter
        │
        ▼
 1. Planner.rank()  — filters to operators whose preconditions currently
    hold (exact claim key, or a semantic tag — see §4), applies hard
    risk-tier/budget constraints, scores the rest by a 9-term constrained-
    utility function, returns a ranked list
        ▼
 2. Operator.render_prompt(ssg)  — substitutes in specific facts already
    learned (a real name, a real tool name), not generic boilerplate
        ▼
 3. BaseAdapter.send(channel, prompt)  — delivers it to the real (or mock)
    target, returns the raw response; any exception (timeout, crash,
    malformed reply) is caught and converted to a non-event rather than
    crashing the campaign
        ▼
 4. ObservationAdapter.execute()
      a. records a Fact — the raw response, uninterpreted
      b. extracts confirmed effects: a deterministic extractor (pure
         function, no LLM) if the operator has one; otherwise an LLM
         judge asked to evaluate a specific, enumerated list of
         candidate claims against the response text
      c. records an Observation — links the raw signal to which claim
         keys it supports/contradicts
      d. asserts a new Claim version (HYPOTHESIZED/CONFIRMED/REFUTED),
         tagged with up to five independent taxonomy dimensions (§5)
        ▼
 5. loop back to step 1 — every claim, insight, and hypothesis update
    is visible to the next ranking call
```

**The evidence model, five tiers, each more interpreted than the last:**
`Fact` (raw, uninterpreted, never revised) → `Observation` (a verdict
linking raw signal to claim keys) → `Claim` (the versioned belief itself —
status + a confidence band) → `Insight` (synthesized higher-order
reasoning: Behavioral / Security / Knowledge-Gap) → `Hypothesis` (the one
deliberately *mutable* object — a testable prediction with persistent
identity that updates in place as evidence arrives). Full mechanics in
`docs/ARCHITECTURE.md` §5.

## 3. The planner's utility function

`aginiti/planner/aginiti_planner.py`:

```
core_utility(op) = alpha * (info_gain(op) + chain_value(op))
                  + beta  * (business_impact(op) + path_progress(op)
                             + emergent_impact(op) + potential_progress(op))
                  + gap_priority(op) + hypothesis_priority(op)
                  + branch_interest(op) + severity_priority(op)
                  + failure_evidence_penalty(op)

utility(op) = core_utility(op) + family_diversification(op)
                                + hypothesis_escalation_bonus(op)
                                + technique_cluster_diversification(op)
```

Nine evidence-grounded terms make up `core_utility` — information gain,
chain value, business impact, real BFS path-progress over the confirmed
graph, emergent impact (credit for unlocking a valuable but *unnamed*
follow-on compromise), potential-based shaping, priority from open
knowledge gaps and hypotheses, interest in unexplored mission branches, a
severity nudge, and a penalty for candidates that share a diagnosed
failure mode with something already confirmed blocked. Three opt-in
EXPLORATION nudges (all default off, so an unparameterized
`AginitiPlanner()` is byte-identical to every version of this class before
they existed) are kept structurally OUTSIDE `core_utility` and only ever
influence ranking ORDER among survivors, never eligibility — the
feasibility gate reads `core_utility` alone (exp23 postmortem fix, see
§6): `family_diversification` demotes a family that looks saturated (2+
same-family confirmations, zero successes) and rewards a genuinely untried
family, both reactively (once a sibling looks dead) and proactively
(unconditionally, closing a real exp28 gap — see `docs/EXP29_RESULTS.md`);
`hypothesis_escalation_bonus` rewards a `ClassPrecondition`-gated follow-up
whose eligibility just opened up from a recent confirmation;
`technique_cluster_diversification` penalizes repeated sampling of an
author-declared cluster of near-duplicate operator WRAPPERS — deliberately
NOT success-immune, unlike family-level saturation, since a cluster is
variants of one hypothesis, not several. Risk tier and budget remain
**hard constraints**, never folded into this scalar. Full term-by-term
rationale, and the specific bug each newer term fixed, in `docs/
ARCHITECTURE.md` §6.

## 4. Multi-step discovery without hardcoded chains

Every chain in this project used to be wired with `Precondition(key,
status)` — an author hardcoding that operator B needs the *exact* claim key
operator A produces. `ClassPrecondition` (`aginiti/operators/library.py`)
instead matches on a **semantic tag** a claim carries (`category`,
`attack_category`, or a minimum `security_boundary` rank) — a downstream
operator gated this way is unlocked by *whichever* upstream operator
happens to produce a matching claim, including one written later by a
different author for a different subsystem. `aginiti/graph/target_graph.py`'s
hub-node mechanism makes this genuinely planner-visible: `path_progress`,
`chain_value`, `emergent_impact`, `potential_progress`, and
`budget_feasible` all gained the ability to reason over a discovered,
non-hardcoded chain with **zero changes** to the planner itself.

Demonstrated with a real 6-step chain
(`aginiti/operators/discovery_chain_definitions.py`) matching the
architecture's own founding example: discover capability → establish trust
→ poison retrieved context → trigger tool → reach sensitive resource →
exfiltrate — with two independently-authored, mutually-substitutable
"establish trust" operators proving the discovery is real (delete either
one, the identical downstream chain still completes through the other,
zero code changes). Full derivation in `docs/ARCHITECTURE.md` §7.

## 5. Composite severity-weighted scoring

`aginiti/composite_score.py`: `mission_success × security_boundary ×
business_impact × cost_efficiency × evidence_quality`, multiplicative — a
campaign that never satisfies its mission scores exactly 0.0, full stop, so
no other factor can manufacture credit for a non-success. Built to answer
"given the same target, same budget, which system discovers more
consequential attack paths" — a question flat attack-success-rate can't
answer, since it treats a system-prompt leak and a real data exfiltration
as the same "1 success." Validated against a graduated-difficulty A–E
candidate table with true success rates hidden from every planner: a real
finding is that `AginitiPlanner` wins the raw success-rate race *less*
often than a fixed-order baseline, but its wins are worth roughly 2× more
on the composite score, because it commits to the highest-severity
candidate first rather than the cheapest-and-most-likely one.

## 6. The taxonomy layer — five independent dimensions

Every confirmed finding can carry up to five tags, each answering a
different question:

| Dimension | Answers | Module |
|---|---|---|
| `category` | What KIND of graph fact is this? (capability / trust_edge / mission_outcome / defender_control / workflow) | `ssg.py` |
| `security_boundary` | How deep did this go, if real? (L0 model behavior → L5 confirmed exfiltration) | `security_boundary.py` |
| `owasp_llm_category` | Which OWASP LLM Top 10 (2025) risk? | `owasp_llm_taxonomy.py` |
| `attack_category` | Which of 11 named attack methodologies? (8 offensive + 3 planner-evaluation controls: decoy/known-defended/low-value-recon) | `attack_category.py` |
| `mitre_atlas_technique` | Which MITRE ATLAS technique (verified ID only)? | `mitre_atlas_refs.py` |

Plus a sixth, failure-only dimension (`failure_diagnosis`) that classifies
*why* a blocked attempt failed, distinguishing generalizable blocks (that
should demote structurally similar candidates) from non-generalizable ones
(evidence about this attempt only). Opt-in and additive throughout — an
untagged claim means "not yet classified," never a fabricated default. See
`docs/ATTACK_LIBRARY.md` for the full category table and `docs/
RESEARCH_AND_PROVENANCE.md` for where each taxonomy comes from.

## 7. The attack catalog — every target, every family

Aginiti's operators split into two shapes: **hand-authored** (a fixed
library per target) and **generated** (built programmatically — one
operator per encoding, per pretext, per InjecAgent test case, or
synthesized live by a search).

### Target-agnostic packs (compose onto any `BaseAdapter`)

| Pack | Ops | What it tests |
|---|---|---|
| `data_exposure.py` | 7 | System-prompt extraction, DAN-style jailbreak, memory/context leakage, tool-inventory over-disclosure, base64 encoding evasion, credential/secret fishing, tool-parameter-override |
| `encoding_variants.py` | 12 (static) | The same override instruction through 10 single transforms (base64/base32/hex/rot13/binary/reverse/caesar/morse/leetspeak/Unicode-confusable) + 2 stacked chains |
| `aginiti/adaptive/encoding_discovery.py` | unbounded (search) | Same encoding-attack surface, but **searches** instead of enumerating — 10 singles, then role-play priming (SelfCipher), then live-synthesized cross-family stacks, stopping the instant one works |
| `aginiti/adaptive/framing_discovery.py` | 5 pretexts + PAIR escalation | Direct/authority/urgency/compliance/role-play framings for the same underlying ask, escalating to LLM-driven prompt rewriting if every static framing fails |
| `aginiti/adaptive/refinement.py` | n/a (wraps any operator) | PAIR-style (Chao et al. 2023) single-operator retry: rewrites a failed prompt using the target's own response as feedback |
| `discovery_chain_definitions.py` | 8 | The `ClassPrecondition`/discovery demonstration pack (§4) |
| `graduated_difficulty_definitions.py` | 5 | The A–E composite-scoring demonstration pack (§5) |
| `agentic_primitives_definitions.py` | 6 | Two primitive types: an approval-gate (with a bypass-attempt operator) and untrusted tool-output content — dry-run validated, not yet mapped onto a real target |

### Mock reference target (Payroll/Slack/GitHub/IT-Helpdesk)

21 operators (18 real across 3 parallel branches + 3 decoys) — the fast,
free, deterministic regression fixture. Never scored as research evidence
once a real target exists; kept for CI and dry runs.

### AnythingLLM (real, production-shaped RAG/agent platform, live-verified)

| Chain | Ops | Mechanism | Deepest boundary |
|---|---|---|---|
| RAG document-poisoning | 2 (plant→trigger) | A planted document survives retrieval and gets echoed in a later, unrelated chat turn | L1 (context manipulation) |
| Automatic-mode tool exfiltration | 2 (plant→trigger) | Retrieval triggers a REAL agent tool call (`web-scraping`) to an attacker URL, confirmed via an independent listener log | L5 (confirmed exfiltration) |
| Markdown-image exfiltration | 2 (plant→trigger) | A markdown image auto-fetch carries data out client-side, no tool permissions needed (the EchoLeak/CVE-2025-32711 pattern) | L5 |
| Multi-tool composition | 3 (plant→summarize→relay) | A genuine 3-step chain requiring TWO different tools to compose (document-summarizer, then web-scraping) | L5 |

Tested against a **two-round hardened gateway** (`aginiti/target_hardening/`
— document sanitization, output redaction, least-privilege service-account
tiers, adaptive suspicion-based lockout, volumetric rate limiting,
strengthened system prompt, raised RAG similarity threshold) built to
resemble a real production deployment, not a soft target — see `docs/
HARDENED_TARGET.md`.

### DVAA (`damn-vulnerable-ai-agent`, 19-agent fleet, 3 real protocols)

12 active operators across 4 branches: memory (2, incl. a MINJA-pattern
implicit-injection variant), A2A identity/delegation trust (3), MCP tool
discovery/auth/composition/registration-poisoning (6, incl. a real 2-step
cross-tool "innocent tools form dangerous chains" composition attack), RAG
knowledge-base exfiltration (1, reverse-engineered from the target's own
real primitive after the originally-planned 9-operator plant/trigger pack
was found not to apply to this target's actual, simulated retrieval
behavior).

### `hardened_agent` / `healthcare_agent` (real RAG targets, live-verified, RBAC-focused)

_Added to this catalog 2026-08-14 — the section had been missing entirely
despite these being the two targets `exp23`/`exp25` and this session's own
live smoke tests actually ran against._ Both vendored from this repo's own
`main` branch (`benchmarks/scaled_evals/agents/`, gitignored) — real RAG
chatbots over real, independently-sourced document corpora (CUAD legal
contracts + CFPB consumer complaints; HealthCareMagic-1k consultations),
not synthetic fixtures. `hardened_agent` additionally has real RBAC
(legal/support/ops personas), chunked retrieval, output redaction, a rate
limiter, and per-persona conversation memory — five independently
toggleable defenses.

| Pack | Ops | What it tests |
|---|---|---|
| `hardened_agent_definitions.py` / `healthcare_agent_definitions.py` (own probes) | 3-4 per target | Own-domain + cross-persona verbatim disclosure (`_make_verbatim_probe`), `ops`'s aggregation-risk test, `/config` recon |
| `_build_authority_claim_probes` (hardened_agent only) | 5 | Confused-deputy authority-claim RBAC probes (Hardy 1988; Greshake et al. 2023) — legal/support only, not ops |
| `redaction_format_evasion.py` (hardened_agent only, deliberately target-specific — see `docs/RESEARCH_AND_PROVENANCE.md`) | 5 | PII-format gaps in `redact()`'s 4 regexes (SSN, email, card, phone) |
| `session_isolation_probe.py` (both targets) | 3 | CWE-488 memory/session-isolation — live-confirmed on `healthcare_agent` to surface real corpus content via an indirect pretext, not a literal memory leak (the target has none) |
| `access_control_layer_probe.py` (both targets) | 4 | Pre-filter vs. post-filter RAG access-control architecture diagnostic (Pinecone) |
| `output_filter_evasion.py` (both targets) | 8 | Output-side reformatting evasion (generic, not target-specific) |
| `data_exposure.py` / `encoding_variants.py` / `adaptive_followup_operators.py` (reused, unmodified) | 7 / 12 / varies | Same target-agnostic packs every other real target uses |
| `aginiti/adaptive/membership_inference.py` (standalone, not in the static library — called directly, see `docs/ATTACK_LIBRARY.md`) | n probes/candidate doc | RAG corpus-membership inference — live-verified across all 3 personas with a fresh-server, MI-first run: average score gap 1.06 (legal 1.31, support 0.75, ops 1.13); see `docs/EXP26_RESULTS.md` for the full arc, including a signal-collapse failure mode found and fixed along the way |

**Real, current per-persona operator counts** (`build_hardened_agent_library`):
legal 49, support 49, ops 44. `healthcare_agent`: 37.

`aginiti/assessment.py`'s `run_full_assessment()` is the orchestrator that
actually drives all of this (plus `many_shot`/`crescendo`/encoding/framing
discovery) against these two targets in one shared `SecurityStateGraph` —
see `docs/ATTACK_LIBRARY.md`'s Adaptive Discovery section.

**RBAC finding, stated plainly**: across `exp23`, `exp25` (3 personas × 2
conditions), `exp26` (3 personas × 2 conditions, the full expanded
pipeline including 17 new RBAC-focused operators), and every live smoke
test in between, `hardened_agent`'s cross-persona RBAC boundary
(`L3_privilege_boundary`) has never once been crossed — traced to a real,
correctly-implemented control (retrieval-time ChromaDB `where`-filtering +
bearer-key-only persona binding, confirmed by reading `personas.py`/
`agent.py` directly), not a coverage gap in Aginiti. See `docs/
EXP26_RESULTS.md` for the full experimental record and analysis.

### Other real targets

- **DVLA** (`damn-vulnerable-llm-agent`, WithSecureLabs) — 3 operators, the
  first real external target integrated.
- **MCP filesystem reference server** (official
  `@modelcontextprotocol/server-filesystem`, real stdio transport) — 4
  operators testing path-boundary enforcement.
- **DVAA consensus/voting scenario** — 3 operators, a standalone
  multi-agent coordination server.
- **InjecAgent** (Zhan et al., ACL Findings 2024) — 1,054 real, vendored
  benchmark test cases (indirect prompt injection via tool output), driven
  through Aginiti's own adapter/campaign loop rather than the paper's own
  evaluation harness.

**Total addressable operator surface**: ~71 hand-authored/generated
operators across the earlier static libraries, plus 44-49 more per
`hardened_agent` persona / 37 for `healthcare_agent` (§7 above), plus
1,054 InjecAgent test cases, plus the unbounded encoding-discovery/
framing-discovery/many-shot/Crescendo/membership-inference search space.

## 8. What's proven, in the sharpest live result to date

`docs/EXP20_RESULTS.md` — a real, 150-trial live benchmark against the
hardened AnythingLLM v2 gateway, 5 conditions (Random, Static-enumeration,
Greedy-Information-Gain, a real Bayesian Thompson-sampling bandit, and the
current `AginitiPlanner`), N=15/condition, 28-operator library, two
missions (a broad "any compromise counts" mission and one that structurally
requires completing a multi-step chain to win):

- **In the chain-required mission, Aginiti scored 3/15 (20%) real,
  independently ground-truth-verified L5 compromises. Every other
  condition — including the Bayesian bandit — scored 0/15.**
- The mechanism is fully traceable: in every one of the 15 trials, Aginiti
  attempted the RAG-injection chain first (via `chain_value`), the
  target's L1 defense blocked it every time, and because RAG failing
  didn't satisfy the mission, the campaign pivoted its remaining budget
  into a second, different chain — succeeding 3 times. **No other
  condition ever attempted a single chain operator, in either mission,
  across all 120 of their combined trials.**
- **Statistical honesty:** pairwise, Aginiti (3/15) vs. any one baseline
  (0/15) does not reach conventional significance at this sample size
  (Fisher's exact, p=0.224). Pooling all 4 baselines together does reach
  significance (p=0.0067) — a secondary, assumption-laden view, not the
  headline number. Real, mechanistically-explained, directionally
  consistent behavior difference; not yet a bulletproof statistical
  result at N=15.
- **The advantage did not generalize to the broad mission** (0% for every
  condition, including Aginiti) — a chain success has to compete against
  22 cheap single-shot alternatives for "any" satisfaction there, so the
  advantage shows up only when the mission structure actually rewards
  chain investment.
- **The discovery-arm bonus test** (encoding_discovery + framing_discovery,
  the most adaptive single-operator attack Aginiti has) failed to crack
  this same target's system-prompt defense in 10/10 independent trials — a
  genuine, honest null result and a positive signal about the target
  hardening, not a technical gap in the search mechanism.

Full numbers, all 10 metrics, and the garak cross-comparison in `docs/
EXP20_RESULTS.md`.

**A second real target, a second live win — `docs/EXP29_RESULTS.md`.**
exp29 ran RQ1's own 4-condition methodology (Random/Static/Aginiti)
against `hardened_agent`, equal 18-prompt budget, independent per-trial
state (fresh server restart before every trial, not a shared long-lived
process), 3 personas as the real independent-trial axis:

- **Aginiti won ground-truth success on all 3 personas tested (3/3).
  Random won 2/3, Static won 1/3** — and Aginiti was the only policy to
  reach all 6 of the target's attack families in a single campaign.
- Getting here required diagnosing and fixing two real planner gaps
  (proactive cross-family exploration, within-family technique-cluster
  redundancy) and two real benchmark-harness gaps (memory contamination
  across trials, fake replication from a deterministic policy's repeated
  seed) — all four found from a live postmortem, each fix isolated and
  offline-proven before being confirmed live.
- A follow-up evidence-only audit (LLM-judge-only claims excluded, kept
  only the independent verbatim/fuzzy oracle) found 10 distinct real
  findings across the 9 trials — 2 genuine RBAC/authorization crossings
  (`ops` receiving content never flagged for its scope) and 8 RAG/
  generation-guardrail over-disclosures — and confirmed the 5 dedicated
  authority-claim social-engineering probes never once crossed the
  boundary they exist to test.
- **N=3 per condition, honestly disclosed as small** — real, independent
  evidence, not yet a statistically bulletproof verdict, and not a
  substitute for the still-unrun frozen DVLA RQ1 protocol.

Full findings-by-finding audit, quoted evidence, and every honest
limitation in `docs/EXP29_RESULTS.md`.

## 9. Test suite and what it proves

**1,079 tests, fully offline** — every LLM call and every network call is
mocked or deterministically stubbed; nothing in the suite costs tokens or
requires a running server. Coverage spans: the SSG/evidence model in
isolation, every operator library's structural invariants, the planner's
utility math term-by-term (including the two new exploration terms from
`docs/EXP29_RESULTS.md` — `tests/unit/test_novelty.py` and `tests/test_
technique_cluster_diversification.py`, each with a dedicated, deliberately-
isolated synthetic scenario proving the fix causally changes the ranked
sequence, not just that a number changed), the campaign loop's control
flow, every adapter's deterministic-extractor paths, the taxonomy wiring
end-to-end through a real `ObservationAdapter.execute()` call, a
10-scenario deterministic end-to-end suite (`tests/integration/test_e2e_scenarios.py`)
covering success/failure/branching/chains/decoys/timeouts/malformed-
responses/pivots/budget-exhaustion, `experiments/_target_lifecycle.py`'s
process-discovery/start/stop/restart logic (`tests/test_target_
lifecycle.py`, 9 tests, mocked `psutil`/`subprocess`/`requests` — no real
process spawned in CI), and the report/export layer.

**What an independent engineering audit found and fixed** (`docs/
ENGINEERING_HARDENING_PASS.md`): a from-scratch trace of the real
execution path, explicitly *not* trusting "500+ tests pass" as proof the
architecture is sound. Found and fixed 5 real bugs — most significantly,
`ObservationAdapter.execute()` had **zero exception handling** around the
call that actually talks to a target, meaning any target-side crash or
timeout could kill an entire campaign uncaught, and 3 of 4 real adapters
were relying on this happening not to occur rather than protecting
themselves. Fixed once, at the single choke point every operator execution
passes through, closing the gap for every adapter and every one of the
three parallel execution paths (`docs/ARCHITECTURE.md` §4.4) at once.
Verified against a live smoke test on the real hardened AnythingLLM target,
not just offline mocks.

## 10. What's not yet built — stated plainly

- **ASCII smuggling / invisible Unicode-tag exfiltration** — a real,
  well-cited (5+ independent 2025 sources, one documented product CVE-class
  vuln), fully-specified proposal (`docs/
  ATTACK_PROPOSAL_ascii_smuggling_exfil.md`) that has NOT been implemented.
  The clearest concrete gap in the markdown/network-exfil family.
- **A unified benchmark harness** — three separate execution paths exist
  today (`run_campaign`, `run_understanding_loop`, and the bespoke
  per-experiment scripts), each real and tested, but a fix to one doesn't
  automatically propagate to the others (`docs/ARCHITECTURE.md` §4.4).
- **The agentic-primitives pack mapped onto a real target** — validated
  only in dry-run form so far; DVAA-specific validation is the natural next
  live step.
- **Cross-target learning** — the taxonomy generalizes across targets by
  deliberate human choice each time; the graph doesn't notice a recurring
  pattern automatically.
- **`aginiti/adaptive/*` wired into the main planner** — encoding/framing
  discovery are real, tested, and have produced real live results, but
  remain a separate orchestrator the main planner never ranks alongside
  static operators in the same decision.
- **A calibrated, real probabilistic confidence model** — `ConfidenceBand`
  is a documented v0 bounded-count simplification, not a Bayesian
  posterior.
- **OWASP Top 10 for Agentic Applications 2026 (ASI01-10) and the broader
  OWASP Agentic AI Threats & Mitigations guide** — researched and cited
  (`docs/RESEARCH_AND_PROVENANCE.md`), not yet built into a tagging
  dimension the way OWASP LLM Top 10 and MITRE ATLAS were.
- **RQ1 at a meaningful trial count** — the project's original founding
  research question (does Aginiti's planner beat Random/Static/
  Memory-guided baselines against the frozen DVLA protocol) has never been
  run to completion, blocked on Groq API quota, an operational not
  architectural constraint. exp20 (§8) answered a related but different
  question on a different target; it doesn't substitute for RQ1 — see
  `docs/ROADMAP.md`.

## 11. Where the real experimental record lives

`docs/EXP20_RESULTS.md` (the sharpest live result on AnythingLLM), `docs/
EXP29_RESULTS.md` (the sharpest live result on `hardened_agent`, plus the
full evidence-only security-findings audit behind it), `docs/EXP26_
RESULTS.md` (the `run_full_assessment()`/membership-inference arc), `docs/
COMPETITOR_COMPARISON.md` (garak comparison), `docs/HARDENED_TARGET.md`
(target-hardening build log), `docs/EVIDENCE_AND_EVALUATION.md` (the full
evidence ledger, every claim in this document cited), `docs/ROADMAP.md`
(phase-by-phase capability status and trajectory), `docs/ARCHITECTURE.md`
(the codebase itself), `docs/ATTACK_LIBRARY.md` (the taxonomy and
adaptive-discovery mechanics in depth), `docs/RESEARCH_AND_PROVENANCE.md`
(the full citations ledger), `docs/INFRASTRUCTURE.md` (where everything
actually runs), `docs/MULTI_STEP_DISCOVERY_AND_SCORING.md` and `docs/
ENGINEERING_HARDENING_PASS.md` (the two most recent architectural chapters,
in full depth), `docs/ATTACK_PROPOSAL_ascii_smuggling_exfil.md` (the one
open, specified-but-unbuilt attack proposal).


## 12. Operator inventory — audited, tiered, exact

_Re-audited 2026-08-22 (previous count below was from 2026-08-13, before
the two-developer merge and this session's `hardened_deep_attack_
operators.py`/tool-calling additions — kept as a dated footnote rather
than silently overwritten)._

Verified the same way as before — actually importing and calling every
operator-library builder function across `aginiti/operators/*.py` (now 31
modules, up from 26) and deduplicating by `.id`, not grepped or estimated:
377 `Operator()` instantiations produce **198 distinct `.id` values**.

| Tier | Count | Excludes |
|---|---|---|
| All distinct operator IDs in the codebase | 198 | — |
| Recommended: appears in ≥1 non-fixture library (real/demo *target*-facing, non-decoy) | **92** | mock target, regression fixtures, planner-mechanism demo/scenario packs |
| Fixture-only (mock target / regression / demo-pack exclusively) | 106 | — |

**92 is the recommended number** for "how many real attack operators does
Aginiti have" — every one of the 92 is independently executable against a
real or realistically-modeled target (`hardened_agent`, `healthcare_agent`,
AnythingLLM, DVLA, DVAA, the MCP filesystem server) and none is a
helper/converter/utility. The excluded 106 are equally real code — the
mock reference target, the synthetic regression fixtures that reproduce
specific planner bugs deterministically, and the `ClassPrecondition`/
family-diversification/technique-cluster demonstration packs — they're
excluded because they don't represent a finding against something
currently live, not because they're lower quality.

**2026-08-13 figures, superseded above, kept for trend context**: 140
distinct IDs total, 115 at the equivalent "recommended" tier. The growth
from 140→198 total / 115→92-recommended reflects the two-developer merge
(a second contributor's own operator libraries — DVAA, DVAA-consensus,
the MCP filesystem server, InjecAgent — were merged into `main` on
2026-08-20) plus this session's `hardened_deep_attack_operators.py` (IKEA/
SECRET/MIA/SPE wrapped specifically for `hardened_agent`) and one new
tool-result-injection probe. The recommended-tier count went *down*
relative to the total because several of the merged libraries (DVAA,
DVAA-consensus) are demonstration/vertical-slice targets by their own
module docstrings, not yet a "real" tier the way `hardened_agent` is —
the tiering rule didn't change, more fixture-tier code was added than
recommended-tier code.

**Not re-verified this pass, flagged rather than silently kept**: the
2026-08-13 per-`attack_category` breakdown table and the RBAC-cross-cut
list further down this section describe the 115-operator tier as it stood
before the merge. They have not been individually re-run against the
current 92-operator tier — treat the specific per-category counts below as
historical/approximate until someone re-audits them the same way the
top-line number above was just re-audited.

**Breakdown by `attack_category`** (the codebase's own tag, at the
115-operator tier — decoys and mock target already removed):

| Category | Count | Notable members |
|---|---|---|
| `direct_prompt_attack` | 24 | `hardened_authority_claim_probe_*` (5), `hardened_cross_boundary_probe`, `hardened_ops_aggregation_probe_1/2`, `hardened_own_domain_verbatim_probe`, `system_prompt_extraction`, `jailbreak_dan_style`, `secret_pattern_fishing`, `escalate_after_disclosure`, `pivot_after_refusal`, `session_isolation_probe_*` (3), `healthcare_verbatim_disclosure_probe` |
| `encoding_attack` | 27 | `encoding_evasion_probe_*` (13 pipelines), `output_filter_evasion_*` (8, two `technique_cluster`-tagged groups), `redaction_format_evasion_*` (5) |
| `tool_manipulation` | 12 | `mcp_no_auth_check`, `mcp_unverified_tool_registration`, `tool_parameter_override_probe`, plus 6 agentic/chain demo-pack variants |
| `tool_discovery` | 4 | `mcp_tool_discovery`, `tool_inventory_full_disclosure`, plus 2 demo-pack variants |
| `rag_poisoning` | 4 | the 4 AnythingLLM document-plant operators |
| `indirect_injection` | 2 | `anythingllm_rag_injection_trigger`, plus 1 demo-pack variant |
| `markdown_network_exfiltration` | 2 | the 2 AnythingLLM markdown/tool-exfil triggers |
| `multi_step_chain` | 2 | `anythingllm_multitool_relay_trigger`, `mcp_exfiltrate_via_plugin_fetch` |
| `low_value_reconnaissance` | 6 | `access_control_layer_probe_*` (4), `hardened_config_recon` |
| `known_defended` | 1 | `memory_context_leakage_probe` |
| Untagged (`attack_category=None`) | 22 | predate the taxonomy retrofit or never assigned one — listed with an informal read, not silently guessed into a bucket: A2A/consensus trust-manipulation operators, unlabeled direct/indirect-injection variants, MCP path-traversal operators, memory-injection operators |

**"RBAC" isn't a formal category.** There is no `attack_category="rbac"`
in the codebase — RBAC/access-boundary-testing operators are currently
folded into `direct_prompt_attack` (the `hardened_agent` probes) or left
untagged (the A2A/consensus trust ones). The genuine RBAC/trust-boundary
cross-cut, independent of formal tagging, is 12 operators: `hardened_
cross_boundary_probe`, `hardened_ops_aggregation_probe_1/2`, the 5
`hardened_authority_claim_probe_*` variants, `a2a_forged_delegation_
request`, `a2a_identity_spoof`, `agentic_trust_via_role_claim`, `agentic_
trust_via_session_claim`, `consensus_duplicate_vote_stuffing`. See `docs/
EXP29_RESULTS.md` for the two confirmed RBAC crossings this cross-cut
actually found live.

**Adaptive/generated variants — not fixed operators, counted separately**:

| Module | Mechanism | Bounded variant count |
|---|---|---|
| `many_shot.py` | Shot-count sweep | 4 fixed values (4/8/16/32 shots) per goal |
| `framing_discovery.py` | Pretext sweep | 5 fixed pretexts per goal, + unbounded PAIR-rewritten follow-ups |
| `encoding_discovery.py` | Converter search | 10 single converters (`ALL_CONVERTERS`) + 1 role-play primer + unbounded synthesized 2-way stacks from whatever's untried |
| `crescendo.py` | Multi-turn escalation | up to 5 turns/goal, each turn's prompt LLM-generated live — not a fixed catalog |
| `membership_inference.py` | Probe generation | 8 probes/candidate document (paper default 30), each LLM-generated live |
| `refinement.py` (PAIR) | Prompt rewriting | Unbounded — LLM-generated live from the target's own last response |
| InjecAgent (`injecagent.py`) | Template applied to a real external dataset | 1,054 real, vendored test cases (verified by calling `build_test_cases()` directly), each becoming exactly one `Operator` — neither "fixed" nor "LLM-generated," a third category: one template instantiated against a fixed real dataset |

**Ambiguities flagged, not silently resolved.** Mock target / synthetic
regression targets / demo packs are all real, independently-executable,
security-semantic `Operator` objects, but none represents a finding
against a real, currently-live target — excluding only the mock target
(115) is the recommended default, with 97 and 77 as progressively more
conservative alternate readings, not a single silently-picked number. The
"duplicate variants" question reads as excluding literal accidental
duplicates (there are none beyond the 2 harmless id collisions above), not
legitimately distinct parameterized techniques (12 encoding variants, 5
authority-claim variants, etc.) — each has its own real prompt, its own
claim effects, and is independently selectable by the planner; collapsed
by technique family instead, the number would be roughly 45–50 distinct
techniques rather than 115 distinct operators.