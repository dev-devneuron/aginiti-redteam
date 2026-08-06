"""Operator framework (design doc Section 13, 15's Operator field reference).

An Operator is the planner-agnostic unit of adversarial action: a formal
precondition/effect specification plus the concrete prompt/action used to
attempt it. `effects_success` / `effects_failure` are *predicted* claim-key
deltas (Section 17's Delta-hat(a)) -- the Observation Adapter reconciles
these predictions against what the target actually does and only applies
the ones the evidence supports.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import SUBGRAPH_DEFENDER, SUBGRAPH_TARGET, SecurityStateGraph

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
