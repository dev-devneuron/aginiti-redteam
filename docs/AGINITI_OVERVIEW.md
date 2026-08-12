# Aginiti — What It Is, How It Works, and What It Can Actually Do

_Written 2026-08-12 as the current single source of truth. Where this
document and an older one (`ARCHITECTURE.md`, `ROADMAP.md`,
`EVIDENCE_AND_EVALUATION.md`) disagree on current state, this document
wins — those three are pointed here and kept for their historical depth.
`docs/ATTACK_LIBRARY.md` and `docs/RESEARCH_AND_PROVENANCE.md` are this
document's companions: the former goes deeper on the attack-category
taxonomy and adaptive-discovery mechanics, the latter is the full
citations ledger._

## Update — 2026-08-12 (second pass, same day): 5 architectural fixes + an
## independent engineering hardening audit

Two more chapters landed the same day this document was first written,
both fully reflected below where they touch existing sections, but with
their own dedicated docs for full depth:

- **[`docs/MULTI_STEP_DISCOVERY_AND_SCORING.md`](MULTI_STEP_DISCOVERY_AND_SCORING.md)**
  — `ClassPrecondition` (multi-step attack-path discovery from semantic
  tags, not hardcoded chains), `composite_score.py` (severity-weighted
  campaign scoring), a graduated-difficulty benchmark pack, two new
  agentic primitive types (approval gates, untrusted tool-output content),
  and a structured failure-diagnosis taxonomy feeding a new
  `failure_evidence_penalty` planner term. §2's utility formula and §3's
  attack catalog below are updated to reflect these.
- **[`docs/ENGINEERING_HARDENING_PASS.md`](ENGINEERING_HARDENING_PASS.md)**
  — an independent, from-scratch architecture audit ("don't assume the
  architecture is correct just because 500+ tests pass"): traced the real
  execution path end-to-end, found and fixed 5 real bugs (2 serious —
  `ObservationAdapter.execute()` had no exception handling around
  `agent.send()` at all, so a target-side crash/timeout could kill an
  entire campaign uncaught; `AnythingLLMAdapter` had no generic failure
  handling), added a 10-scenario deterministic end-to-end test suite, and
  ran a live smoke test against the real hardened AnythingLLM target.
  837/837 tests passing.

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
  read the target and craft a chain by hand — it doesn't scale and
  doesn't leave behind a structured, queryable record.

Aginiti's bet: treat this as **planning under uncertainty over an
evidence graph**, not scripted enumeration. A claim about the target
(`"the agent trusts a self-reported identity"`, `"a planted document
survives retrieval and gets acted on"`) is asserted with a confidence
level, gets revised as more evidence arrives, and directly changes what
the planner tries next.

## 2. How it works

```
Mission + OperatorLibrary + SecurityStateGraph + Policy/Planner + BaseAdapter
        │
        ▼
 1. Planner.rank()  — filters to operators whose preconditions currently
    hold, applies hard risk-tier/budget constraints, scores the rest by
    a constrained-utility function (below), returns a ranked list
        ▼
 2. Operator.render_prompt(ssg)  — substitutes in specific facts already
    learned (a real name, a real tool name), not generic boilerplate
        ▼
 3. BaseAdapter.send(channel, prompt)  — delivers it to the real (or
    mock) target, returns the raw response
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
         tagged with up to four independent taxonomy dimensions (§5)
        ▼
 5. loop back to step 1 — every claim, insight, and hypothesis update
    is visible to the next ranking call
```

**The evidence model, five tiers, each more interpreted than the last:**
`Fact` (raw, uninterpreted, never revised) → `Observation` (a verdict
linking raw signal to claim keys) → `Claim` (the versioned belief itself
— status + a confidence band) → `Insight` (synthesized higher-order
reasoning: Behavioral / Security / Knowledge-Gap) → `Hypothesis` (the one
deliberately *mutable* object — a testable prediction with persistent
identity that updates in place as evidence arrives). Full mechanics in
`ARCHITECTURE.md` §5-6 — unchanged since it was written.

**The planner's utility function** (`aginiti/planner/aginiti_planner.py`,
current form — three terms added since `ARCHITECTURE.md` §6):

```
utility(op) = alpha * (info_gain(op) + chain_value(op))
            + beta  * (business_impact(op) + path_progress(op)
                       + emergent_impact(op) + potential_progress(op))
            + gap_priority(op) + hypothesis_priority(op)
            + branch_interest(op) + severity_priority(op)
            + failure_evidence_penalty(op)
```

- `chain_value` — a plant operator gets discounted (0.5x) credit for its
  declared downstream trigger's own value, so a genuinely valuable
  multi-step chain can outrank a mediocre single-step decoy — the exact
  gap found and fixed this chapter (was structurally impossible before).
- `severity_priority` — an unscaled additive nudge toward higher
  `security_boundary` (L0-L5) findings, the planner's first-ever
  awareness of finding *severity*, not just claim resolution.
- `failure_evidence_penalty` (added same-day, second pass) — a negative,
  bounded, additive nudge: if a CONFIRMED failure claim anywhere in the
  graph carries a **generalizable** `failure_diagnosis` tag (`blocked_by_
  privilege`, `blocked_by_network_egress`, `blocked_by_approval_gate` —
  see `aginiti/graph/failure_diagnosis.py`) and a candidate operator's own
  prospective failure would carry the identical tag, that candidate is
  demoted. Reuses `ClassPrecondition`'s exact tag-matching idea, applied
  to negative instead of positive evidence — the literal mechanism behind
  "given what I just learned, what's now more/less promising."
- Risk tier and budget remain **hard constraints** on the candidate set,
  never folded into this scalar.

**Multi-step discovery without hardcoded chains** (added same-day, second
pass): every chain before this point (below) was wired with `Precondition`
— an author hardcoded that operator B needs the EXACT claim key operator A
produces. `ClassPrecondition` (`aginiti/operators/library.py`) instead
matches on the SEMANTIC TAG a claim carries (`category`, `attack_category`,
or a minimum `security_boundary` rank) — a downstream operator gated this
way is unlocked by *whichever* upstream operator happens to produce a
matching claim, including one written later by a different author for a
different subsystem. `aginiti/graph/target_graph.py`'s new hub-node
mechanism (`category_hub()`/`attack_category_hub()`/`boundary_hub()`)
makes this genuinely planner-visible: every one of `path_progress`/
`chain_value`/`potential_progress`/`budget_feasible` gained the ability to
reason over a discovered, non-hardcoded chain with **zero changes** to
`aginiti_planner.py` itself. Demonstrated with a real 6-step chain
(`aginiti/operators/discovery_chain_definitions.py`) matching the
architecture's own founding example verbatim: discover capability →
establish trust → poison retrieved context → trigger tool → reach
sensitive resource → exfiltrate — with two independently-authored,
mutually-substitutable "establish trust" operators proving the discovery
is real (delete either one, the identical downstream chain still
completes through the other, zero code changes). Full derivation,
including a real cost-accounting bug this change introduced and fixed
(hub traversal was initially double-counted as a real operator hop), in
`docs/MULTI_STEP_DISCOVERY_AND_SCORING.md`.

**Composite severity-weighted scoring** (`aginiti/composite_score.py`,
added same day): `mission_success × security_boundary × business_impact ×
cost_efficiency × evidence_quality`, multiplicative — a campaign that never
satisfies its mission scores exactly 0.0, full stop, so no other factor can
manufacture credit for a non-success. Built specifically to answer "given
the same target, same budget, which system discovers more consequential
attack paths" — a question flat attack-success-rate can't answer, since it
treats a system-prompt leak and a real data exfiltration as the same
"1 success." Validated against a real graduated-difficulty A–E candidate
table (`aginiti/operators/graduated_difficulty_definitions.py`, 5
candidates spanning a genuine cost/probability/severity tradeoff, true
success rates hidden from every planner) — real finding: `AginitiPlanner`
wins the raw success-rate race LESS often than a fixed-order baseline, but
its wins are worth ~2x more on the composite score, because it commits to
the highest-severity candidate first rather than the cheapest-and-most-
likely one.

## 3. The attack catalog — every target, every family

Aginiti's operators split into two shapes: **hand-authored** (a fixed
library per target) and **generated** (built programmatically — one
operator per encoding, per pretext, per InjecAgent test case, or
synthesized live by a search). Counts below are exact (`len(library)` at
time of writing), not estimates.

### Target-agnostic packs (no target-specific vocabulary — compose onto any `BaseAdapter`)

| Pack | Ops | What it tests |
|---|---|---|
| `data_exposure.py` | 7 | System-prompt extraction, DAN-style jailbreak, memory/context leakage, tool-inventory over-disclosure, base64 encoding evasion, credential/secret fishing, tool-parameter-override (misuse) |
| `encoding_variants.py` | 12 (static) | The same override instruction through 10 single transforms (base64/base32/hex/rot13/binary/reverse/caesar/morse/leetspeak/Unicode-confusable) + 2 stacked chains |
| `aginiti/adaptive/encoding_discovery.py` | unbounded (search) | Same encoding-attack surface, but **searches** instead of enumerating — 10 singles, then role-play priming (SelfCipher), then live-synthesized cross-family stacks, stopping the instant one works |
| `aginiti/adaptive/framing_discovery.py` | 5 pretexts + PAIR escalation | Direct/authority/urgency/compliance/role-play framings for the same underlying ask, escalating to LLM-driven prompt rewriting if every static framing fails |
| `aginiti/adaptive/refinement.py` | n/a (wraps any operator) | PAIR-style (Chao et al. 2023) single-operator retry: rewrites a failed prompt using the target's own response as feedback |
| `discovery_chain_definitions.py` (added 2026-08-12) | 8 | Genuine 6-step chain (discover → establish trust → poison context → trigger tool → reach resource → exfiltrate) gated ONLY by `ClassPrecondition`, plus 2 decoys — the ClassPrecondition/discovery demonstration pack, see §2 above |
| `graduated_difficulty_definitions.py` (added 2026-08-12) | 5 | The A–E graduated-difficulty candidate table (independently-varied cost/severity, true success probability hidden from the planner) — the composite-scoring demonstration pack, see §2 above |
| `agentic_primitives_definitions.py` (added 2026-08-12) | 6 | Two new primitive TYPES: an approval-gate (a sensitive action gated behind a second confirmation step, with a bypass-attempt operator) and untrusted tool-output content (a tool's own RETURN VALUE, not its input or a RAG document, carrying an embedded instruction) — target-agnostic, dry-run validated only; mapping onto a real target (DVAA) is explicitly deferred, see `docs/MULTI_STEP_DISCOVERY_AND_SCORING.md` §Issue 3 |

### Mock reference target (Payroll/Slack/GitHub/IT-Helpdesk)

21 operators (18 real across 3 parallel branches + 3 decoys) — the fast,
free, deterministic regression fixture. Never scored as research
evidence once a real target exists; kept for CI and dry runs.

### AnythingLLM (real, production-shaped RAG/agent platform, live-verified)

| Chain | Ops | Mechanism | Deepest boundary |
|---|---|---|---|
| RAG document-poisoning | 2 (plant→trigger) | A planted document survives retrieval and gets echoed in a later, unrelated chat turn | L1 (context manipulation) |
| Automatic-mode tool exfiltration | 2 (plant→trigger) | Retrieval triggers a REAL agent tool call (`web-scraping`) to an attacker URL, confirmed via an independent listener log | L5 (confirmed exfiltration) |
| Markdown-image exfiltration | 2 (plant→trigger) | A markdown image auto-fetch carries data out client-side, no tool permissions needed (the EchoLeak/CVE-2025-32711 pattern) | L5 |
| Multi-tool composition | 3 (plant→summarize→relay) | A genuine 3-step chain requiring TWO different tools to compose (document-summarizer, then web-scraping) — Aginiti's flagship multi-step-chain example, real AND-precondition composition | L5 |

Tested against a **two-round hardened gateway** (`aginiti/target_hardening/`
— document sanitization, output redaction, least-privilege service-account
tiers, adaptive suspicion-based lockout, volumetric rate limiting,
strengthened system prompt, raised RAG similarity threshold) built to
resemble a real production deployment, not a soft target — see
`docs/HARDENED_TARGET.md`.

### DVAA (`damn-vulnerable-ai-agent`, 19-agent fleet, 3 real protocols)

12 active operators across 4 branches: memory (2, incl. a MINJA-pattern
implicit-injection variant), A2A identity/delegation trust (3), MCP tool
discovery/auth/composition/registration-poisoning (6, incl. a real
2-step cross-tool "innocent tools form dangerous chains" composition
attack), RAG knowledge-base exfiltration (1, the target's own real
primitive, reverse-engineered from source after the originally-planned
9-operator plant/trigger pack was found to not apply to this target's
actual — simulated, non-persistent — retrieval behavior).

### Other real targets

- **DVLA** (`damn-vulnerable-llm-agent`, WithSecureLabs) — 3 operators,
  the first real external target integrated.
- **MCP filesystem reference server** (official
  `@modelcontextprotocol/server-filesystem`, real stdio transport) — 4
  operators testing path-boundary enforcement.
- **DVAA consensus/voting scenario** — 3 operators, a standalone
  multi-agent coordination server.
- **InjecAgent** (Zhan et al., ACL Findings 2024) — 1,054 real, vendored
  benchmark test cases (indirect prompt injection via tool output),
  driven through Aginiti's own adapter/campaign loop rather than the
  paper's own evaluation harness.

**Total addressable operator surface**: ~71 hand-authored/generated
operators across static libraries, plus 1,054 InjecAgent test cases,
plus the unbounded encoding-discovery/framing-discovery search space.

## 4. Not yet built — stated plainly

- **ASCII smuggling / invisible Unicode-tag exfiltration** — a real,
  well-cited (5+ independent 2025 sources, one documented product CVE-class
  vuln), fully-specified proposal (`docs/
  ATTACK_PROPOSAL_ascii_smuggling_exfil.md`) that has NOT been
  implemented. The clearest concrete gap in the markdown/network-exfil
  family.
- **Cross-target learning** — the taxonomy generalizes across targets by
  deliberate human choice each time; the graph doesn't notice a
  recurring pattern automatically.
- **Multi-step attack-graph search beyond one BFS hop's shortest-path
  reasoning** — `path_progress`/`chain_value` handle real chains, but
  there's no weighing of multiple candidate paths against each other.
- **A calibrated, real probabilistic confidence model** — `ConfidenceBand`
  is a documented v0 bounded-count simplification, not a Bayesian
  posterior.
- **Planner integration for the adaptive-discovery modules** —
  `encoding_discovery.py`/`framing_discovery.py` are standalone
  orchestrators today, not first-class candidates the main planner ranks
  alongside static operators.
- **OWASP Top 10 for Agentic Applications 2026 (ASI01-10) and the
  broader OWASP Agentic AI Threats & Mitigations guide** — researched
  and cited (`docs/RESEARCH_AND_PROVENANCE.md`), not yet built into a
  tagging dimension the way OWASP LLM Top 10 and MITRE ATLAS were.

## 5. The taxonomy layer — four independent dimensions

Every confirmed finding can carry up to four tags, each answering a
different question, threaded through `ClaimEffect` → `SecurityStateGraph`
→ `ObservationAdapter` → the Target Profile report → the visualization
export:

| Dimension | Answers | Module |
|---|---|---|
| `category` | What KIND of graph fact is this? (capability / trust_edge / mission_outcome / defender_control / workflow) | `ssg.py` |
| `security_boundary` | How deep did this go, if real? (L0 model behavior → L5 confirmed exfiltration) | `security_boundary.py` |
| `owasp_llm_category` | Which OWASP LLM Top 10 (2025) risk? | `owasp_llm_taxonomy.py` |
| `attack_category` | Which of 11 named attack methodologies? (8 offensive + 3 planner-evaluation controls: decoy/known-defended/low-value-recon) | `attack_category.py` |
| `mitre_atlas_technique` | Which MITRE ATLAS technique (verified ID only)? | `mitre_atlas_refs.py` |

Opt-in and additive throughout — an untagged claim means "not yet
classified," never a fabricated default. See `docs/ATTACK_LIBRARY.md`
for the full category table and `docs/RESEARCH_AND_PROVENANCE.md` for
where each taxonomy comes from.

## 6. Test suite and what it proves

**770 tests, fully offline** — every LLM call and every network call is
mocked or deterministically stubbed; nothing in the suite costs tokens or
requires a running server. Coverage spans: the SSG/evidence model in
isolation, every operator library's structural invariants (unique ids,
tagged effects, judge-description coverage — a project-wide regression
guard added 2026-08-12 after a real gap was found this way), the planner's
utility math term-by-term, the campaign loop's control flow, every
adapter's deterministic-extractor paths, the taxonomy wiring end-to-end
through a real `ObservationAdapter.execute()` call, and the report/export
layer.

**What live runs (not unit tests) have actually shown:**
- **exp16 (tight-budget validation, mock/multi-branch target)**: the
  planner reliably found "one extremely reliable winner" — real evidence
  of correct discrimination, but on a comparatively easy problem, which
  became the direct motivation for hardening the target further.
- **exp17/18 (hardened AnythingLLM, live)**: `tool_inventory_full_disclosure`
  leaked 50.7% of the time (38/75) under an unguarded "integration audit"
  pretext — a real finding that directly motivated a system-prompt fix
  any production admin would make.
- **exp19 (Aginiti vs. garak, live, same hardened target)**: 4 of 5
  comparable categories agreed exactly between the two tools (0% attack
  success — the hardened target genuinely held). The 5th (encoding) was
  investigated at the trace level and found NOT to be a fair comparison
  — garak's own detector scores "success" on decode-and-echo compliance,
  not on hidden-instruction execution. Full numbers and the honest
  bottom line: `docs/COMPETITOR_COMPARISON.md`.
- **Architecture-review dry runs (2026-08-12, fully offline)**: confirmed
  the full pipeline end-to-end against (a) a near-total-refusal simulated
  hard agent and (b) a genuine 3-step precondition chain — found and
  fixed a real crash (`export.py` on a live `ExecutionResult`, not just
  saved-trial JSON) and a real judge-blind-spot bug (three operator-
  generation modules built claim keys the judge could never look up a
  description for) in the process.

**What's still an open question, honestly**: the project's original
founding research question — does Aginiti's SSG-driven planner beat
Random/Static-enumeration/Memory-guided baselines at a statistically
meaningful sample size — was never completed in its originally-scoped
frozen-DVLA-protocol form (blocked on Groq API quota, an operational not
architectural constraint; see `ROADMAP.md`'s "How we got here"). The
project's center of gravity moved to real-target hardening and external
comparison instead, which answered a different, also-real question
("does this hold up against a hardened target, and against a credible
external tool") without answering the original one.

## 7. Where the real experimental record lives

`docs/COMPETITOR_COMPARISON.md` (garak comparison, current), `docs/
HARDENED_TARGET.md` (target-hardening build log), `docs/
EVIDENCE_AND_EVALUATION.md` (the DVLA/DVAA/consensus-era ledger, through
2026-08-09), `docs/ROADMAP.md` (phase-by-phase capability status, same
era). `docs/ATTACK_LIBRARY.md` goes deeper on the taxonomy and adaptive-
discovery mechanics summarized in §3/§5 above. `docs/
RESEARCH_AND_PROVENANCE.md` is the full citations ledger for everything
referenced in building any of this.
