"""Operator framework (design doc Section 13, 15's Operator field reference).

An Operator is the planner-agnostic unit of adversarial action: a formal
precondition/effect specification plus the concrete prompt/action used to
attempt it. `effects_success` / `effects_failure` are *predicted* claim-key
deltas (Section 17's Delta-hat(a)) -- the Observation Adapter reconciles
these predictions against what the target actually does and only applies
the ones the evidence supports.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from aginiti.attacks.base import BaseAttack
from aginiti.connectors.endpoint import AgentEndpoint
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import (
    CATEGORY_CAPABILITY,
    CATEGORY_DEFENDER_CONTROL,
    SUBGRAPH_DEFENDER,
    SUBGRAPH_TARGET,
    SecurityStateGraph,
)

# Fallback phrases used when a template variable has no captured detail yet
# (e.g. the claim exists but the judge didn't extract a specific fact from
# the raw signal) -- keeps rendered prompts grammatical either way.
_TEMPLATE_FALLBACKS = {
    "payroll_detail": "the payroll record on file",
}


@dataclass(frozen=True)
class Precondition:
    key: str
    status: ClaimStatus  # HYPOTHESIZED means "any non-refuted claim on this key satisfies it"


@dataclass(frozen=True)
class ClassPrecondition:
    """A precondition satisfied by ANY currently-current claim matching a
    SEMANTIC CLASS, not one specific declared key -- added 2026-08-12 as
    the mechanism for genuine multi-step attack-path discovery (design doc
    directive: "don't tell Aginiti the chain. It should discover it from
    observations").

    `Precondition` above is exact-key matching: operator B requires the
    SPECIFIC claim key a human predicted operator A would produce. That is
    100% author-declared wiring -- every chain in this project before this
    (anythingllm_rag_*, anythingllm_automatic_*, anythingllm_markdown_*,
    anythingllm_multitool_*) is exactly that: a human wrote
    `Precondition("anythingllm_document_planted", CONFIRMED)` into the
    trigger operator, so the trigger can ONLY ever be unlocked by that one
    named plant operator, even though nothing about the trigger's own
    prompt or mechanism actually depends on which specific operator
    produced the antecedent fact.

    ClassPrecondition instead matches on the TAGS already carried by every
    claim in this codebase (ssg.py's CATEGORY_* / attack_category.py /
    security_boundary.py -- established, independently-maintained
    dimensions, not new machinery invented for this purpose): "any
    CONFIRMED claim tagged category=trust_edge", or "any CONFIRMED claim
    tagged attack_category=rag_poisoning", or "any CONFIRMED claim at
    security_boundary rank >= 2". A downstream operator gated this way is
    unlocked by WHATEVER operator happens to produce a matching claim --
    including one written after the downstream operator, by a different
    author, targeting a completely different subsystem. That is the actual
    discovery mechanism: the planner's candidate set changes because of
    what was semantically LEARNED, not because a human pre-wired an exact
    key into a precondition tuple.

    At least one of category/attack_category/min_security_boundary_rank
    must be set (__post_init__ raises otherwise) -- an all-None instance
    would silently match the FIRST currently-current tagged claim
    regardless of what it actually represents, which is not "genuinely
    permissive," it's a latent correctness bug (an accidental universal
    unlock). Combining more than one field means AND (every set field must
    match the same claim key), for precision when a class needs to be
    narrower than a single tag (e.g. "a trust_edge specifically established
    via indirect_injection," not any trust_edge at all).

    See Operator.preconditions_met() for the matching semantics (mirrors
    exact-key Precondition's HYPOTHESIZED-means-wildcard-status rule for
    consistency) and aginiti/graph/target_graph.py's category_hub() /
    attack_category_hub() / boundary_hub() for how this same class concept
    becomes real, planner-visible GRAPH EDGES -- not just a candidate-set
    gate -- so path_progress/chain_value/potential_progress reason over
    discovered chains with zero changes to aginiti_planner.py."""
    category: str | None = None
    attack_category: str | None = None
    min_security_boundary_rank: int | None = None
    status: ClaimStatus = ClaimStatus.CONFIRMED

    def __post_init__(self) -> None:
        if self.category is None and self.attack_category is None and self.min_security_boundary_rank is None:
            raise ValueError(
                "ClassPrecondition needs at least one of category / attack_category / "
                "min_security_boundary_rank -- an all-None instance would match any tagged "
                "claim at all, which is never the intent."
            )


@dataclass(frozen=True)
class ClaimEffect:
    key: str
    status: ClaimStatus
    subgraph: str = SUBGRAPH_TARGET
    object: str = "true"
    weight: int = 1  # Section 17 Eq. 14.1 per-claim-type Information Gain weight
    # What KIND of claim this is (trust_edge, mission_outcome, ...) -- see
    # ssg.py's CATEGORY_* constants. Left unset by most operator
    # definitions (defaults to CAPABILITY, or DEFENDER_CONTROL for
    # defender-subgraph effects) and only overridden explicitly where the
    # claim represents a trust relationship or a mission outcome, since
    # those are the categories the analyst queries (queries.py) care about.
    category: str | None = None
    # Optional judge-facing description for THIS effect, overriding the
    # global aginiti/adapter/observation_adapter.py KEY_DESCRIPTIONS
    # lookup when set (2026-08-08 architecture audit fix). Exists for
    # operator packs generated programmatically per-instance (e.g.
    # aginiti/operators/injecagent.py's one-per-test-case operators),
    # where mutating the shared global KEY_DESCRIPTIONS dict from a
    # factory function is exactly the kind of global-mutable-state smell
    # this field replaces -- a description travels WITH its effect now,
    # not registered as a side effect of calling a constructor. None
    # (the default) preserves every existing operator's behavior
    # unchanged: they all still resolve through KEY_DESCRIPTIONS.
    description: str | None = None
    # Which real-world trust boundary this effect represents if CONFIRMED
    # -- see aginiti/graph/security_boundary.py's BOUNDARY_L0..L5 constants
    # and that module's own docstring for the full rubric and why this is
    # deliberately opt-in rather than inferred/retrofitted onto every
    # operator at once. None (the default, BOUNDARY_UNSPECIFIED once it
    # reaches the SSG) preserves every existing operator's behavior
    # unchanged.
    security_boundary: str | None = None
    # Which OWASP Top 10 for LLM Applications (2025) risk category this
    # effect represents if CONFIRMED -- see aginiti/graph/
    # owasp_llm_taxonomy.py for the full 10-category list and why it's a
    # separate dimension from security_boundary/category. Same opt-in
    # discipline: None (the default) preserves every existing operator's
    # behavior unchanged.
    owasp_llm_category: str | None = None
    # Which attack METHODOLOGY this effect represents -- see aginiti/graph/
    # attack_category.py for the 11-category list (8 offensive techniques +
    # 3 planner-evaluation controls: decoy/known_defended/low_value_recon).
    # A fourth, orthogonal dimension alongside category/security_boundary/
    # owasp_llm_category. Same opt-in discipline.
    attack_category: str | None = None
    # A verified MITRE ATLAS (atlas.mitre.org) technique ID, e.g.
    # "AML.T0070" -- see aginiti/graph/mitre_atlas_refs.py for the short,
    # deliberately-incomplete list of IDs this project has actually
    # confirmed rather than guessed. None (the default, and the common
    # case) means "not yet verified against ATLAS," not "no ATLAS
    # technique applies."
    mitre_atlas_technique: str | None = None
    # WHY this effect represents a failure, structurally -- see
    # aginiti/graph/failure_diagnosis.py for the 5-category taxonomy and
    # why this is deliberately meaningful ONLY on effects_failure entries
    # (a success effect has nothing to "diagnose"; setting this on a
    # success effect is harmless but meaningless -- no code reads it
    # there). Same opt-in discipline as every other tag: None (the
    # default) preserves every existing operator's behavior unchanged,
    # and means "not yet diagnosed," not "no diagnosis applies."
    failure_diagnosis: str | None = None

    def __post_init__(self) -> None:
        if self.category is None:
            inferred = CATEGORY_DEFENDER_CONTROL if self.subgraph == SUBGRAPH_DEFENDER else CATEGORY_CAPABILITY
            object.__setattr__(self, "category", inferred)


@dataclass(frozen=True)
class Operator:
    id: str
    description: str
    prompt: str
    channel: str  # "direct" | "slack"
    preconditions: tuple[Precondition, ...]
    effects_success: tuple[ClaimEffect, ...]
    effects_failure: tuple[ClaimEffect, ...]
    cost_prompts: int
    risk_tier: RiskTier
    framework_signature: str | None = None
    # Which subsystem/attack surface this operator belongs to (e.g. "payroll",
    # "github", "helpdesk") -- an explicit declared fact, not something
    # inferred from id/key-name conventions (the exact kind of hidden,
    # undocumented coupling that made Static-enumeration's declaration
    # order an unexamined confound in the first place, see
    # docs/EVIDENCE_AND_EVALUATION.md Section 0). None for target libraries
    # that haven't been tagged yet (DVLA/DVAA/MCP) -- branch propagation
    # (aginiti/graph/belief_state.py) treats an untagged claim as a no-op,
    # never an error, so this rolls out per-library without breaking the
    # others. Orthogonal to ClaimEffect.category: category says WHAT KIND
    # of claim this is (trust_edge, mission_outcome, ...); branch says
    # WHICH SUBSYSTEM it's about. Both are needed for propagation to answer
    # "a trust edge just confirmed in branch A -- which OTHER branches have
    # an unresolved claim of that SAME category" without any LLM call.
    branch: str | None = None
    # (from_node, to_node): what confirming this operator's success effect
    # means structurally, e.g. ("slack_trust", "payroll_write_unauthorized").
    # This is what aginiti/graph/target_graph.py turns into a real graph
    # edge once the effect is actually confirmed -- the substrate for the
    # planner's path-based reasoning (aginiti/planner/aginiti_planner.py's
    # path_progress), not just flat claim-key bookkeeping.
    graph_edge: tuple[str, str] | None = None
    # {template_var: claim_key} -- render_prompt() substitutes each
    # `{template_var}` in `prompt` with the *specific fact* the judge
    # extracted for that claim (Claim.object), not just "true"/"false".
    # This is what makes an attack "mindful" of the target rather than a
    # canned script: the injected/social-engineering message references
    # what was actually learned (e.g. the real employee name pulled from a
    # payroll lookup) instead of generic boilerplate.
    template_vars: dict[str, str] = field(default_factory=dict)
    # Every probe answers a security-understanding question independent of
    # whether it also lands as an exploit -- e.g. "does the agent verify
    # identity before disclosing account data?" This is what makes
    # "operators are probes first, exploits second" literal metadata
    # instead of only a design narrative. Optional (defaults to "") so the
    # older mock library isn't forced to backfill it retroactively.
    understanding_question: str = ""
    # Optional deterministic bypass for the LLM judge: a pure function
    # raw_signal -> list of confirmed effect ids ("<key>::<status>"). Set
    # only when the response is ALREADY structured data (e.g. an MCP
    # tools/list JSON-RPC result) that needs no interpretation -- "no
    # speculation, deterministic reasoning where possible." None (the
    # default) leaves every existing operator on the judge-based path,
    # unchanged.
    extractor: Callable[[str], list[str]] | None = None
    # Semantic-class preconditions -- see ClassPrecondition's own docstring.
    # Defaults to () so every existing operator (all exact-key `preconditions`)
    # is completely unaffected; ANDed with `preconditions` in
    # preconditions_met() -- both tuples must be satisfied, so an operator can
    # mix "this exact setup claim" with "any trust edge from anywhere."
    precondition_classes: tuple[ClassPrecondition, ...] = ()
    # A FINER-grained grouping than `attack_category` -- added 2026-08-14
    # in direct response to a real live finding (exp28's postmortem):
    # `attack_category` (11 broad categories) is too coarse to tell apart
    # "5 near-duplicate wrapper templates around the SAME underlying
    # question" (e.g. hardened_agent_definitions.py's
    # `_build_authority_claim_probes` -- one probe, 5 authority-claim
    # framings) from "a genuinely different technique that happens to
    # share the same broad category" (e.g. `system_prompt_extraction`,
    # `jailbreak_dan_style` -- both `direct_prompt_attack` too, but
    # nothing like each other mechanically). Live exp28 kept sampling
    # authority_claim_probe variants because each carries its own real,
    # undiminished info_gain/business_impact (a genuinely different claim
    # key) -- exactly the SAME structural pattern `aginiti/graph/
    # novelty.py`'s family-level saturation already handles for whole
    # families, just one level finer. None (the default, the common case)
    # means "this operator is its own singleton cluster" -- completely
    # unaffected, matching every other opt-in tag in this dataclass. Set
    # ONLY on operators generated by a "same idea, different wrapper/
    # format/template" loop (see aginiti/graph/novelty.py's
    # `technique_cluster_diversification_term` for how this is used, and
    # the specific packs retrofitted with it) -- never on hand-authored,
    # mechanically distinct operators; guessing a shared cluster onto
    # operators that don't actually share a mechanism would be worse than
    # leaving them untagged.
    technique_cluster: str | None = None
    # -- Deep-attack fields (added 2026-08-20, Phase 2 Slice D, plans/
    # phase2-operator-wrapping.md) -- extends Operator rather than forking
    # a parallel type, so rank()/budget_feasible()/OperatorLibrary/every
    # existing call site keeps typing `list[Operator]` uniformly; only
    # ObservationAdapter.execute() needs to branch on `kind`. All five
    # default to values that make an unmodified `Operator(...)` call
    # behave exactly as before this addition -- kind="prompt" is what
    # every operator defined before this slice implicitly was.
    #
    # kind: "prompt" (default, every existing operator) routes through
    # ObservationAdapter's original render_prompt/send/judge pipeline
    # unchanged. "deep_attack" routes through the new
    # _execute_deep_attack branch instead -- prompt/channel/preconditions/
    # effects_success/effects_failure above are still REQUIRED fields on
    # this frozen dataclass for a deep_attack operator (no schema fork),
    # but are not used for rendering/judging in that path; author them as
    # honest documentation (e.g. prompt="[runs IKEAAttack.execute_black_box
    # internally, not a single templated prompt]") rather than functional
    # content.
    kind: Literal["prompt", "deep_attack"] = "prompt"
    # Builds the BaseAttack subclass instance for a deep_attack operator,
    # given the shared AgentEndpoint (HTTPAgentAdapter's own `.endpoint`,
    # see aginiti/adapters/http_agent_adapter.py) -- e.g.
    # `lambda ep: IKEAAttack(target_url=..., llm_provider=..., api_key=...,
    # endpoint=ep)`. Called fresh on every execution (an Operator instance
    # is reused across an OperatorLibrary's lifetime, so this must not
    # cache/mutate a single BaseAttack instance across calls). None for
    # every "prompt" operator -- required (enforced at call time, not by
    # this dataclass) for "deep_attack".
    attack_factory: Callable[[AgentEndpoint], BaseAttack] | None = None
    # Forwarded as **kwargs to attack.execute_black_box(...) -- e.g.
    # {"max_queries": 20, "topic": "HR records"} for IKEAAttack. Never
    # execute() or execute_with_traces(): deep-attack operators are
    # explicitly Tier-1/black-box only, matching the "no attack requires
    # OTel/traces for real Tier-1 findings" project-wide rule -- there is
    # no ambiguity about which path runs.
    attack_kwargs: dict = field(default_factory=dict)
    # The single claim key a deep_attack operator's findings translate
    # onto (aginiti/core/finding_translation.py's translate_findings_to_
    # claims) -- a bare string, same open string-typed convention every
    # other claim key in this codebase already uses (no enum/registry).
    # Reuse an EXISTING key where one already means the same thing (e.g.
    # "system_prompt_disclosed", already produced by
    # data_exposure_operators()'s cheap single-shot probe) rather than
    # inventing a synonym, so a lightweight probe and a deep attack
    # confirming the SAME underlying fact converge on one claim, not two.
    claim_key: str | None = None
    # Wall-clock budget (seconds) for attack.execute_black_box(...) itself
    # -- NOT part of the originally-approved 4-field design doc list,
    # added during implementation because the design doc's own text calls
    # for "a wall-clock timeout guard... inside _execute_deep_attack" and
    # a guard needs a real, per-operator-configurable number to guard
    # with (a single hardcoded constant can't be right for both a
    # max_queries=2 smoke-test operator and a max_queries=20+ production
    # one). Flagged here as an implementation-time addition to the
    # approved design, not silently introduced. 300.0 (5 minutes) is a
    # generous default sized for a real multi-query deep attack (each
    # query involves several of its own LLM/embedding/HTTP calls); a
    # cheaper attack's Operator definition should set this lower.
    attack_timeout_seconds: float = 300.0

    def render_prompt(self, ssg: SecurityStateGraph) -> str:
        if not self.template_vars:
            return self.prompt
        values = {}
        for var, claim_key in self.template_vars.items():
            claim = ssg.current_claim(claim_key)
            detail = claim.object if claim and claim.object and claim.object != "true" else None
            values[var] = detail or _TEMPLATE_FALLBACKS.get(var, "")
        return self.prompt.format(**values)

    def preconditions_met(self, ssg: SecurityStateGraph) -> bool:
        for pre in self.preconditions:
            claim = ssg.current_claim(pre.key)
            if claim is None:
                return False
            if claim.status == ClaimStatus.REFUTED:
                return False
            if pre.status != ClaimStatus.HYPOTHESIZED and claim.status != pre.status:
                return False
        for cpre in self.precondition_classes:
            if not self._class_precondition_met(cpre, ssg):
                return False
        return True

    def _class_precondition_met(self, cpre: ClassPrecondition, ssg: SecurityStateGraph) -> bool:
        """Is there ANY currently-current, non-refuted claim matching every
        field `cpre` sets? See ClassPrecondition's own docstring for why
        this is the actual chain-discovery mechanism -- this scan is the
        only place that mechanism lives; target_graph.py's hub edges are a
        SEPARATE, planner-visibility-only mirror of the same idea (a
        confirmed-only edge into a shared hub node), not the source of
        truth for eligibility.

        Candidate keys are the union of every key ever tagged with
        category/attack_category/security_boundary at all (most keys in a
        real campaign have at least one of these tags by now, given how
        pervasively this project's operator packs set them) -- narrowed by
        whichever of cpre's three fields are actually set, then confirmed
        against that key's CURRENT claim/status exactly as exact-key
        Precondition does."""
        from aginiti.core.graph.security_boundary import rank as boundary_rank

        candidate_keys = set(ssg.claim_category) | set(ssg.claim_attack_category) | set(ssg.claim_boundary)
        for key in candidate_keys:
            if cpre.category is not None and ssg.claim_category.get(key) != cpre.category:
                continue
            if cpre.attack_category is not None and ssg.claim_attack_category.get(key) != cpre.attack_category:
                continue
            if cpre.min_security_boundary_rank is not None:
                level = ssg.claim_boundary.get(key)
                if level is None or boundary_rank(level) < cpre.min_security_boundary_rank:
                    continue
            claim = ssg.current_claim(key)
            if claim is None or claim.status == ClaimStatus.REFUTED:
                continue
            if cpre.status != ClaimStatus.HYPOTHESIZED and claim.status != cpre.status:
                continue
            return True
        return False

    def predicted_keys(self) -> set[str]:
        return {e.key for e in self.effects_success} | {e.key for e in self.effects_failure}


class OperatorLibrary:
    def __init__(self, operators: list[Operator]):
        self._by_id = {op.id: op for op in operators}

    def __iter__(self):
        return iter(self._by_id.values())

    def __len__(self):
        return len(self._by_id)

    def get(self, operator_id: str) -> Operator:
        return self._by_id[operator_id]

    def candidates(self, ssg: SecurityStateGraph) -> list[Operator]:
        return [op for op in self._by_id.values() if op.preconditions_met(ssg)]

    def by_category(self, *categories: str) -> "OperatorLibrary":
        """Filter to operators whose attack methodology matches one of the
        given `attack_category` values (see aginiti/core/graph/
        attack_category.py's `ALL_CATEGORIES`/`CATEGORY_TITLES` for the
        11 named groups: 8 real offensive techniques -- direct_prompt_
        attack, encoding_attack, rag_poisoning, indirect_injection,
        tool_discovery, tool_manipulation, markdown_network_exfiltration,
        multi_step_chain -- plus 3 planner-evaluation controls -- decoy,
        known_defended, low_value_reconnaissance). Returns a NEW
        OperatorLibrary; does not mutate self, matching `candidates()`'s
        own read-only style above.

        Deliberately reuses `attack_category.py`'s own canonical
        `operator_primary_family()` rather than re-deriving "which
        category does this operator belong to" here -- that function's own
        docstring exists specifically because this exact rule (first
        tagged effects_success entry, else first tagged effects_failure
        entry) had already been independently reinvented three times
        before it was consolidated; a fourth inline copy here would be
        exactly the drift that consolidation was meant to prevent.
        Imported locally, not at module level, for the same circular-
        import reason `operator_primary_family`'s own docstring states
        (attack_category.py -> this module has no reverse edge).

        An operator with no tagged attack_category at all (still common on
        the older, pre-2026-08-12 DemoAgent mock library -- see this
        project's own scripts/run_campaign.py module docstring, 'Tier
        classification', for the same caveat stated about --tier)
        `operator_primary_family()` returns None for, and None can never
        equal a real category string, so such an operator is silently
        excluded from every category filter rather than raising -- the
        same "untagged means excluded, not an error" contract every other
        opt-in taxonomy field in this codebase already follows.

        Raises ValueError immediately (not a silent empty result) for a
        caller mistake -- no categories given, or a category name that
        does not exist -- so a typo is caught at the call site instead of
        surfacing later as "the library filtered down to nothing and I
        don't know why"."""
        from aginiti.core.graph.attack_category import ALL_CATEGORIES, operator_primary_family

        if not categories:
            raise ValueError(
                "by_category() needs at least one category -- see "
                "aginiti.core.graph.attack_category.ALL_CATEGORIES for the full list."
            )
        unknown = [c for c in categories if c not in ALL_CATEGORIES]
        if unknown:
            raise ValueError(
                f"Unknown attack_category value(s): {unknown!r}. Valid categories are: "
                f"{sorted(ALL_CATEGORIES)}."
            )
        wanted = set(categories)
        return OperatorLibrary([
            op for op in self._by_id.values() if operator_primary_family(op) in wanted
        ])
