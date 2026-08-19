"""IndependentFinding -- the general, target-agnostic extension point that
lets an adapter report evidence a target's real response actually contains,
INDEPENDENT of whatever a specific operator's own narrow extractor (or LLM
judge) concluded from that same text. Added 2026-08-14 in direct response
to a real, live-diagnosed gap (exp23): `HardenedAgentAdapter` already
carried a deterministic, non-LLM `FuzzyDisclosureIndex`/
`VerbatimDisclosureIndex` capable of catching a genuine content disclosure
an operator's own extractor missed, but that oracle was wired ONLY into
`ground_truth_mission_achieved()` -- an adapter-level, POST-HOC benchmark-
scoring check the SSG/planner never saw. The planner could not reason
from, chain off of, or even report a finding its own independent oracle
had already confirmed.

Fact -> Observation -> Claim -> Evidence, preserved exactly (see aginiti/
adapter/observation_adapter.py's `execute()` for where this is wired in):
  Fact         a NEW Fact (kind="independent_evidence") carrying this
               finding's own structured data -- auditable, never silently
               folded into the existing response_text Fact.
  Observation  a new Observation links that Fact to a NEW, operator-scoped
               claim key.
  Claim        `ssg.assert_claim(...)` asserts it CONFIRMED -- the SAME
               method every other claim in this codebase goes through,
               never a bypass.
  Evidence     the claim carries `security_boundary` (REQUIRED here, never
               Optional) and `attack_category` exactly like any other
               tagged claim, so TargetBeliefState / family_diversification
               / hypothesis_escalation_bonus / severity_priority all pick
               it up automatically, with zero planner-side special-casing.

This does NOT weaken the evidence standard anywhere: it is STRICTLY
ADDITIVE (a new, uniquely-keyed claim, never overwriting or bypassing the
operator's own extractor-confirmed claims), and the oracle behind it is
typically STRONGER evidence than the usual per-operator path -- deterministic
content matching against the real underlying corpus, not an LLM judgment
call at all.

Deliberately NOT part of the required `BaseAdapter` Protocol -- same
optional-extension pattern as `record_suspicious_event()` (aginiti/
adapters/base.py): `ObservationAdapter.execute()` calls it via
`getattr(agent, "independent_evidence_check", None)` and no-ops when
absent, so every existing adapter (DemoAgent, AnythingLLMAdapter,
DVAAAdapter, ...) is completely unaffected. Implementing it is entirely the
adapter's own choice -- the MECHANISM here is general-purpose; only an
adapter that actually has an independent oracle (HardenedAgentAdapter/
HealthcareAgentAdapter's fuzzy/verbatim disclosure indices) wires it in."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IndependentFinding:
    """One independently-verified piece of evidence about a single target
    response. `claim_suffix` is appended to the executing operator's own
    id to form a unique, operator-scoped claim key (e.g. operator id
    "encoding_v3" + suffix "independent_disclosure_confirmed" ->
    "encoding_v3_independent_disclosure_confirmed") -- scoped per-operator
    so two different operators' independent findings never collide, and so
    the finding is always traceable back to exactly which action produced
    it, same as every other claim in this codebase.

    `security_boundary` is REQUIRED, not Optional, and deliberately not
    defaulted to anything -- an adapter implementing `independent_evidence_
    check()` MUST make an explicit, code-level (never LLM-inferred)
    decision about what boundary level its own concrete evidence check
    justifies. There is no "let the LLM decide how serious this is" path
    anywhere in this dataclass; see aginiti/graph/security_boundary.py's
    own L0-L5 rubric for what a real adapter should pick and why.

    `attack_category` is optional -- when the adapter doesn't specify one,
    ObservationAdapter falls back to the EXECUTING OPERATOR's own declared
    family (aginiti/graph/attack_category.py's `operator_primary_family()`
    -- the same rule aginiti/graph/target_belief.py and aginiti/graph/
    novelty.py already use), so this new claim participates in family-
    level saturation/diversification bookkeeping exactly like any other
    claim from that same operator would.

    `evidence_ref` is a short, concrete, auditable reference -- e.g. "fuzzy
    match: doc hcm_0215, 3 shingles" or a matched substring -- NOT free
    prose summarizing what an LLM thinks happened. It becomes the claim's
    `object` value and is written into the accompanying Fact, so a human
    (or a later automated audit) can always see exactly what concrete
    evidence justified this claim, not just that "something was found.\""""
    claim_suffix: str
    security_boundary: str
    attack_category: str | None = None
    evidence_ref: str = ""
