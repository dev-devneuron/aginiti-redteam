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

from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import (
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
        return True

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
