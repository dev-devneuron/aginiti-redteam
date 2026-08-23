# Aginiti — Attack Library: Taxonomy, Catalog, and Adaptive Discovery

_Last updated 2026-08-14. The deep-dive companion to `docs/
AGINITI_OVERVIEW.md` §6–7 — read that first for the summary; this document
is the full taxonomy reference and the mechanics of how the adaptive-search
modules work._

---

## The 11-category attack-methodology taxonomy (`aginiti/graph/attack_category.py`)

A fourth tagging dimension on `ClaimEffect`, alongside `category`
(graph-fact kind), `security_boundary` (how deep, L0-L5), and
`owasp_llm_category` (OWASP LLM Top 10 2025). Answers "what attack
METHODOLOGY is this":

| Category | Meaning | Example operators |
|---|---|---|
| `direct_prompt_attack` | Single-turn, user-channel manipulation | `system_prompt_extraction`, `jailbreak_dan_style`, `secret_pattern_fishing` |
| `encoding_attack` | Obfuscation/transformation-based evasion | `encoding_evasion_probe`, every `encoding_variants.py`/`encoding_discovery.py` operator |
| `rag_poisoning` | Planting malicious content into a retrieval index | Every AnythingLLM chain's *plant* step |
| `indirect_injection` | Instruction execution triggered via retrieved/tool-output content | AnythingLLM RAG trigger, every `injecagent.py` operator |
| `tool_discovery` | Enumerating/disclosing available tools | `tool_inventory_full_disclosure`, `mcp_tool_discovery` |
| `tool_manipulation` | Invoking a real tool outside its intended scope/authorization | `tool_parameter_override_probe`, `mcp_no_auth_check`, `mcp_unverified_tool_registration` |
| `markdown_network_exfiltration` | Confirmed data egress via markdown auto-fetch or tool-driven network call | Automatic-mode and markdown-exfil chain triggers |
| `multi_step_chain` | Genuine AND-composition across 2+ independently-confirmed operators | `anythingllm_multitool_relay_confirmed`, `mcp_exfiltrate_via_plugin_fetch` |
| `decoy` | Planner-evaluation control: structurally valid, connects to no mission node | The 3 mock-library decoys |
| `known_defended` | Planner-evaluation control: an operator this project has documented as reliably refused | `memory_context_leakage_probe` |
| `low_value_reconnaissance` | Planner-evaluation control: low intrinsic value but opens a real path | `recon_capabilities`, `recon_github_access`, `probe_helpdesk_capability` |

The last three are not offensive techniques — see `OFFENSIVE_CATEGORIES`/
`is_offensive()` to exclude them from "how many real attack techniques
does Aginiti cover" reporting.

### Selecting by category — `OperatorLibrary.by_category()` (2026-08-22)

This taxonomy was originally purely descriptive (a tag read by the
planner's `family_diversification` term and by reporting code) — there
was no way, from a script or the CLI, to say "load only the encoding
attacks" or "only RAG poisoning." `OperatorLibrary.by_category(*categories)`
(`aginiti/operators/library.py`) closes that: it returns a NEW
`OperatorLibrary` containing only the operators whose category matches one
of the ones given (a union across multiple categories, not an
intersection). It resolves each operator's category through
`operator_primary_family()` — the same canonical helper `family_
diversification` already uses (see that function's own docstring for why
it's the one place this classification rule lives, after being
independently reinvented three times before consolidation) — so a
`by_category()` filter can never silently disagree with what the planner
itself considers an operator's category to be.

```python
from aginiti.operators.library import OperatorLibrary
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.deep_attack_operators import deep_attack_operators

library = OperatorLibrary([*data_exposure_operators(), *deep_attack_operators()])
encoding_only = library.by_category("encoding_attack")
encoding_or_rag = library.by_category("encoding_attack", "rag_poisoning")  # union
```

Raises `ValueError` immediately — not a silently-empty result — if given
zero categories or a name that isn't in `ALL_CATEGORIES` (a typo caught at
the call site, not discovered later as "why did this run nothing").
Untagged operators (`attack_category=None`, still common on the older
DemoAgent mock library — see `docs/AGINITI_OVERVIEW.md` §12's own
"Untagged" row in its per-category breakdown for how many) never match
any category filter, the same "opt-in tag, excluded rather than errored
when absent" contract every taxonomy dimension in this project follows.

`scripts/run_campaign.py --attack-category CATEGORY [CATEGORY ...]` wraps
this directly as a CLI flag, alongside the coarser, pre-existing `--tier`
flag (which derives from OWASP/attack_category tags into just 3 buckets —
`data_leakage`/`unauthorized_actions`/`discovery_recon` — rather than
exposing the full 11-category taxonomy). The two are mutually exclusive.
Run `python scripts/run_campaign.py --list-attack-categories` to print
every valid category name with a one-line description before choosing —
covered end to end (unit tests for `by_category()` itself, plus a live,
manually-verified CLI run per category-path) in
`tests/unit/test_operator_library.py`.

### `technique_cluster` — a finer grain than `attack_category` (2026-08-14)

`attack_category` groups by METHODOLOGY (11 broad categories) — too
coarse to tell "5 near-duplicate wrapper templates around one question"
apart from "5 genuinely different techniques that happen to share a
methodology." `Operator.technique_cluster` (opt-in, `None` for the common,
untagged case) lets an author declare that a set of operators are wrapper
VARIANTS of one underlying hypothesis, not independent techniques — feeding
`technique_cluster_diversification` (`docs/ARCHITECTURE.md` §6), added in
direct response to a real exp28 live finding (`docs/EXP29_RESULTS.md`):
the planner kept re-sampling variants of one already-answered question
instead of moving to a genuinely different technique in the same family.

| Cluster | Members | Verified shared mechanism |
|---|---|---|
| `hardened_authority_claim_probe_variants` | 5 | Same cross-domain question, 5 different social-engineering framings (`_AUTHORITY_CLAIM_TEMPLATES`) |
| `session_isolation_probe_variants` | 3 | Same "does cross-session memory leak" question, 3 different pretexts |
| `output_filter_evasion_system_prompt_variants` | 5 | Same "does an output-filter reformatting trick let the system prompt through" question, 5 reformatting tricks |
| `output_filter_evasion_secret_variants` | 3 | Same question for a credential/secret instead of the system prompt |

**Deliberately NOT applied to every candidate 5-variant-in-one-factory-
function pack.** `redaction_format_evasion.py`'s 5 variants were inspected
individually and left untagged — each targets a DIFFERENT PII type's
specific regex gap (SSN vs. email vs. credit card vs. phone), a genuinely
different hypothesis per variant, not a wrapper of one repeated question.
Guessing a shared cluster onto operators that don't actually share a
mechanism would be worse than leaving them untagged — see that module's
own docstring for the full reasoning. `encoding_variants.py`'s 13 base
pipelines are similarly untagged: each is a genuinely distinct encoding
scheme (base64, rot13, hex, morse, ...), not a wrapper of one idea. This
audit has not yet been run over the full 115-operator library — see
`docs/ARCHITECTURE.md` §12 for what's confirmed still open.

## The failure-diagnosis taxonomy (`aginiti/graph/failure_diagnosis.py`)

A sixth, failure-only tagging dimension, deliberately small: five
categories, three **generalizable** (a confirmed instance is real
structural evidence about *other* operators, feeding
`AginitiPlanner.failure_evidence_penalty()` — see `docs/ARCHITECTURE.md`
§6) and two deliberately **non-generalizable**:

| Diagnosis | Generalizable? | Meaning |
|---|---|---|
| `blocked_by_privilege` | Yes | The tool/action exists, but this credential cannot invoke it |
| `blocked_by_network_egress` | Yes | An outbound request was attempted and blocked by a network-level control |
| `blocked_by_approval_gate` | Yes | A sensitive action required a confirmation step that wasn't obtained |
| `not_retrieved` | No | The specific attempt didn't surface the relevant content — evidence about this attempt only |
| `actively_refused` | No | The target declined this one request — evidence about this attempt only |

## MITRE ATLAS cross-reference (`aginiti/graph/mitre_atlas_refs.py`)

A short, deliberately incomplete list of **verified** (live-searched, not
recalled) MITRE ATLAS technique IDs — `AML.T0051.000`/`.001` (direct/
indirect prompt injection), `AML.T0054` (jailbreak), `AML.T0070` (RAG
poisoning), `AML.T0086` (exfiltration via tool invocation). Only operators
with a real, checkable match are tagged; an untagged operator means "not
yet cross-referenced," never a claim of no applicable technique.

Also researched but not yet built into a tagging module: **OWASP Top 10
for Agentic Applications 2026** (ASI01 Agent Goal Hijack .. ASI10 Rogue
Agents, released 2025-12-09) and the broader **OWASP Agentic AI Threats
and Mitigations** guide (Feb 2025, covering Agent Design/Memory/Planning &
Autonomy/Tool Use/Deployment). A natural next tagging dimension, read as
carefully as the LLM Top 10 and ATLAS were here.

## The full operator catalog

See `docs/AGINITI_OVERVIEW.md` §7 for the complete, current table (packs,
per-target chains, and total operator counts) — kept in exactly one place
so the two documents can't drift apart on a number. This document's job is
the taxonomy and the discovery mechanics below, not the catalog itself.

---

## Adaptive discovery (`aginiti/adaptive/`)

Seven modules now (four as of 2026-08-13; three added 2026-08-14 in
direct response to a live postmortem finding these engines had never
actually been pointed at a real target's own campaign — see
`aginiti/assessment.py` below, which is the ORCHESTRATOR that closed the
"disconnected from AginitiPlanner" gap this section used to describe as a
standing limitation. It no longer is one.

- **`variant_discovery.py`** — the generic engine. `run_variant_discovery`
  calls a domain-supplied `next_candidate_fn(trial_history)` for up to
  `max_trials` rounds, executing each candidate Operator through the real
  `ObservationAdapter`/SSG path and stopping the instant one succeeds.
  Domain logic decides *what* to try next; this module only owns *whether
  to keep going*. Also the engine `many_shot.py` reuses directly (below).
- **`encoding_discovery.py`** — the flagship application. Where
  `encoding_variants.py` fires a fixed list of 12 pipelines,
  `run_encoding_chain_discovery` SEARCHES: 10 single converters, then
  `SelfCipherPrimerConverter` (pure role-play priming, no literal
  encoding), then SYNTHESIZED cross-family stacks (an "opaque" transform
  paired with a "shape-preserving" one — CipherChat's own family split,
  arXiv:2308.06463) built on the fly from what hasn't been tried yet.
  Research-grounded in CipherChat and MetaCipher (arXiv:2506.22557, 2025
  AAAI — adaptive cipher *selection* reaching SOTA attack success within
  ~10 queries). Genuinely different in kind from a static enumeration, not
  just a longer list.
- **`framing_discovery.py`** — proves the engine generalizes. Sweeps 5
  structurally different pretexts (direct/authority/urgency/compliance/
  role-play) for the *same* underlying direct-prompt-attack goal, and
  escalates to `refinement.py`'s PAIR-style LLM rewriting if every static
  framing fails.
- **`refinement.py`** — PAIR-style (Chao et al. 2023) single-operator
  retry loop, used standalone or as `framing_discovery`'s last-resort
  escalation tier.
- **`many_shot.py`** *(2026-08-14)* — many-shot jailbreaking (Anil et al.,
  Anthropic 2024). Embeds a sweep of shot counts (4/8/16/32 fabricated,
  deliberately bland/generic in-context Q&A exchanges — never real harmful
  content) into ONE message per trial via `variant_discovery.py`'s engine,
  exploiting long-context in-context learning rather than a single-turn
  pretext or encoding — a genuinely different mechanism from every other
  module here.
- **`crescendo.py`** *(2026-08-14)* — Crescendo multi-turn escalation
  (Russinovich/Salem/Eldan, Microsoft 2024, arXiv:2404.01833). Drafts each
  turn LIVE from the target's own actual prior responses (an LLM call,
  injectable via `generate_turn_fn` for testing), gradually escalating
  across REAL turns rather than fabricating fake ones in a single message
  — the structural opposite of `many_shot.py`, both real, both now wired
  into the same orchestrator.
- **`membership_inference.py`** *(2026-08-14)* — the Interrogation Attack
  (Naseh et al., "Riddle Me This! Stealthy Membership Inference for
  Retrieval-Augmented Generation," arXiv:2502.00306, 2025): does a SPECIFIC
  candidate document exist in a target's retrieval corpus, tested via
  natural-sounding yes/no questions (never jailbreak-flavored ones) rather
  than direct content extraction. `calibrate_threshold_from_held_out()`
  runs the same procedure against KNOWN non-members — the first thing in
  this codebase to actually use `hardened_dataset_held_out.json`, which
  `prepare_hardened_dataset.py`'s own docstring had named as ground truth
  for exactly this since before the technique existed here. Live-verified
  2026-08-14 against `hardened_agent`: a real ingested document scored
  1.0 (4/4 correct, specific answers) vs a real held-out document scoring
  -0.125 (3/4 "I don't know") — clean separation at n=4, less than half
  the paper's own default n=30. **Scope, stated honestly**: this proves
  corpus membership WITHIN a persona's own authorized domain — it is not
  an RBAC-boundary-crossing technique (see `docs/HARDENED_TARGET.md`'s
  access-control-architecture section for why a cross-persona variant
  would show zero signal on a pre-filter target like this one).

  **A real duplicate, found during the 2026-08-22 merge audit, disclosed
  rather than silently picked around:** `aginiti/attacks/mia/
  interrogation.py` (the other developer's own codebase, merged in via
  `main`) independently implements the SAME paper (arXiv:2502.00306) —
  two developers built the Interrogation Attack from the same citation
  without either knowing about the other's work. The two are not
  identical: this module is wired into `run_full_assessment()`'s
  sequential discovery-phase pipeline (`aginiti/assessment.py`);
  `interrogation.py` is wrapped as a true, budget-competing `Operator`
  (`aginiti/operators/deep_attack_operators.py` for its generic/dev-
  fixture form, `aginiti/operators/hardened_deep_attack_operators.py` for
  its `hardened_agent`-specific, real-corpus form) that `AginitiPlanner`
  ranks directly alongside every other operator — a genuinely different
  integration shape, not just a rename. Both are real, tested, and
  currently kept; **not consolidated in this pass** — a real, open
  architectural decision for whoever picks this up next, not silently
  resolved here.

All seven are fully unit-tested with deterministic stub adapters/
extractors/LLM-call injection points — no live LLM or target calls in any
test (`many_shot.py`/`crescendo.py`/`membership_inference.py` each follow
the SAME "inject a deterministic stand-in for any LLM-drafting function
via an explicit parameter" pattern `refinement.py` established first).
**Live-tested twice now**: exp20's discovery-arm bonus test (`docs/
EXP20_RESULTS.md`, `encoding_discovery`/`framing_discovery` only, 10
trials, a genuine null result against a hardened AnythingLLM target); and
`aginiti/assessment.py`'s `run_full_assessment()` (2026-08-14, exp25 plus
this session's smoke tests) — the orchestrator that runs ALL of the above
in sequence over one shared `SecurityStateGraph`, so a claim confirmed by
any phase is real evidence the LATER phases (and the final normal
`AginitiPlanner` campaign phase) can see and build on, not four/seven
disconnected experiments. Stops the instant any phase produces a
GROUND-TRUTH-CORROBORATED success (`_corroborated()` — requires the
target's own independent oracle to agree, not just an LLM judge call; see
`docs/EVIDENCE_AND_EVALUATION.md` for the live false-positive pattern that
made this necessary and the live confirmation that it now works).
