"""The Security State Graph store (design doc Section 10, 16.2).

Append-only: Claims and Observations are never mutated or deleted. "Current
state" for a given claim key is a query over the append log (latest claim
with that key), not a stored table -- this is what Section 10.3 calls a
"free consequence" of the provenance design.

Confidence (Section 11.2, v0): a bounded, weighted count of supporting minus
contradicting Observations for a claim key, mapped to a discrete band. This
is the documented simplification the design doc flags as replaceable later
without a schema change.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from aginiti.graph.belief_state import CampaignBeliefState
from aginiti.graph.hypothesis import Hypothesis, normalize_statement
from aginiti.graph.schema import (
    Claim,
    ClaimStatus,
    ConfidenceBand,
    Fact,
    Insight,
    InsightCategory,
    Observation,
    StructuralNode,
    next_id,
)

# Section 10.1's five sub-graphs, used to tag which claims/nodes belong to
# which view. "operator_self" and "mission" are tracked as separate
# structures below rather than as claim tags, since they aren't
# subject/predicate assertions about the target.
SUBGRAPH_TARGET = "target"
SUBGRAPH_DEFENDER = "defender"

# Orthogonal to subgraph: subgraph says *whose* claim this is (what the
# attacker observed vs. what the defender did); category says *what kind*
# of claim it is. This is what makes "which trust assumptions did the agent
# reveal" answerable as a direct query instead of eyeballing claim keys --
# without it, a trust relationship (planner_trusts_slack) and a bare
# capability check (payroll_api_exists) are indistinguishable except by
# reading the key name.
CATEGORY_CAPABILITY = "capability"        # the agent has/exposes some tool or access
CATEGORY_TRUST_EDGE = "trust_edge"        # the agent trusts a source/actor without independent verification
CATEGORY_WORKFLOW = "workflow"            # a multi-step process or gate the agent follows
CATEGORY_MISSION_OUTCOME = "mission_outcome"  # a mission success-criterion was reached
CATEGORY_DEFENDER_CONTROL = "defender_control"  # something blocked/flagged an attempt


def _confidence_band(net_score: int) -> ConfidenceBand:
    bounded = max(0, min(net_score, 4))
    if bounded <= 1:
        return ConfidenceBand.LOW
    if bounded in (2, 3):
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.HIGH


@dataclass
class OperatorStats:
    executions: int = 0
    successes: int = 0
    failures: int = 0

    @property
    def success_rate(self) -> float:
        return self.successes / self.executions if self.executions else 0.0


@dataclass
class SecurityStateGraph:
    structural_nodes: dict[str, StructuralNode] = field(default_factory=dict)
    facts: list[Fact] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    insights: list[Insight] = field(default_factory=list)
    hypotheses: dict[str, Hypothesis] = field(default_factory=dict)  # normalized statement -> Hypothesis
    operator_stats: dict[str, OperatorStats] = field(default_factory=dict)
    claim_subgraph: dict[str, str] = field(default_factory=dict)  # claim key -> subgraph tag
    claim_category: dict[str, str] = field(default_factory=dict)  # claim key -> category tag
    claim_boundary: dict[str, str] = field(default_factory=dict)  # claim key -> security_boundary tag (aginiti/graph/security_boundary.py)
    # Derived working memory (aginiti/graph/belief_state.py) -- a CACHE over
    # the fields above, not another source of truth. Deliberately excluded
    # from persistence.py; see that module's comment.
    belief: CampaignBeliefState = field(default_factory=CampaignBeliefState)

    # -- structural nodes ----------------------------------------------
    def add_structural_node(self, node: StructuralNode) -> StructuralNode:
        self.structural_nodes[node.id] = node
        return node

    def nodes_of_type(self, cls: type) -> list[StructuralNode]:
        return [n for n in self.structural_nodes.values() if isinstance(n, cls)]

    # -- facts -------------------------------------------------------------
    def record_fact(self, operator_execution_id: str, kind: str, data: dict) -> Fact:
        """Records a Fact -- see schema.py's module docstring for the Fact/
        Observation/Claim tiering. Called BEFORE judge interpretation runs
        (ObservationAdapter.execute()), so a fact is recorded whether or
        not anything ends up being inferred from it."""
        fact = Fact.create(operator_execution_id, kind, data)
        self.facts.append(fact)
        return fact

    # -- insights ------------------------------------------------------
    def record_insight(self, category: InsightCategory, statement: str,
                        derived_from: tuple[str, ...] = (), confidence: str | None = None,
                        alternative_explanations: tuple[str, ...] = (),
                        evidence_still_missing: tuple[str, ...] = (), importance: str | None = None,
                        prior_belief: str | None = None, related_probe_id: str | None = None,
                        priority_weight: float | None = None) -> Insight:
        """Records a synthesized piece of higher-order knowledge -- see
        schema.py's Insight docstring for the tiering this sits atop, and
        for which fields matter for which category (BEHAVIORAL/SECURITY
        vs. KNOWLEDGE_GAP). Grounding claim keys and probe ids are the
        caller's (aginiti/graph/insights.py) responsibility, not this
        method's. `priority_weight` (optional, KNOWLEDGE_GAP only -- see
        schema.py's Insight docstring) defaults to None for every existing
        caller; only aginiti/graph/priors.py's cold-start seeding sets it."""
        insight = Insight.create(category, statement, derived_from, confidence,
                                 alternative_explanations, evidence_still_missing,
                                 importance, prior_belief, related_probe_id, priority_weight)
        self.insights.append(insight)
        return insight

    # -- hypotheses ------------------------------------------------------
    def form_hypothesis(self, statement: str, target_claim_key: str, expected_status: ClaimStatus,
                         experiments: tuple[str, ...], prior_confidence: float = 0.5) -> Hypothesis:
        """Get-or-create by normalized statement: calling this again for
        the same underlying hypothesis (e.g. a later synthesis round
        re-raising the same gap) MERGES the experiment list into the
        existing tracked object rather than creating a duplicate -- this
        is what gives a hypothesis a stable identity across rounds/
        campaigns, unlike Insight's append-only log. If the target claim
        is already resolved by the time this is called (the matched
        experiment ran in an earlier round, before this hypothesis was
        even formed), the resolution is applied immediately rather than
        waiting for a future assert_claim call that may never come."""
        key = normalize_statement(statement)
        existing = self.hypotheses.get(key)
        if existing is not None:
            existing.experiments = tuple(sorted(set(existing.experiments) | set(experiments)))
            return existing

        hyp = Hypothesis.create(statement, target_claim_key, expected_status, experiments, prior_confidence)
        self.hypotheses[key] = hyp
        current = self.current_claim(target_claim_key)
        if current is not None:
            hyp.apply_claim_status(current.status)
        return hyp

    def _update_hypotheses_for_claim(self, key: str, status: ClaimStatus) -> None:
        for hyp in self.hypotheses.values():
            if hyp.target_claim_key == key:
                hyp.apply_claim_status(status)

    # -- claims / observations -------------------------------------------
    def current_claim(self, key: str) -> Claim | None:
        for claim in reversed(self.claims):
            if claim.key == key:
                return claim
        return None

    def current_status(self, key: str) -> ClaimStatus | None:
        claim = self.current_claim(key)
        return claim.status if claim else None

    def is_confirmed(self, key: str) -> bool:
        return self.current_status(key) == ClaimStatus.CONFIRMED

    def record_observation(
        self,
        operator_execution_id: str,
        raw_signal: str,
        supports: tuple[str, ...] = (),
        contradicts: tuple[str, ...] = (),
    ) -> Observation:
        """Append-only ingest of one Observation (Section 16.2's update()).
        Any claim key referenced in supports/contradicts gets a new Claim
        version whose confidence is recomputed from every Observation ever
        linked to that key. Status is left as-is here -- callers that need
        to assert a status transition (hypothesized -> confirmed, etc.)
        should call `assert_claim` for that key immediately after, or before,
        recording the observation, using this same observation's id.
        """
        obs = Observation.create(operator_execution_id, raw_signal, supports, contradicts)
        self.observations.append(obs)
        for key in set(supports) | set(contradicts):
            self._recompute_confidence(key)
        return obs

    def assert_claim(self, key: str, object_: str, status: ClaimStatus,
                      subgraph: str = SUBGRAPH_TARGET, category: str | None = None,
                      security_boundary: str | None = None) -> Claim:
        """Create a new Claim version for `key` with an explicit status.
        Confidence is derived from whatever Observations already reference
        this key (0 if none yet -> LOW). `category` is optional because the
        internal auto-hypothesize path (_recompute_confidence) doesn't know
        it -- leaving the prior tag (or none, defaulting to "capability" for
        queries) in place is correct there, since the real category was
        already set (or will be) by the assert_claim call driven by the
        operator's ClaimEffect. `security_boundary` follows the exact same
        optional, sticky-until-overwritten pattern -- see aginiti/graph/
        security_boundary.py."""
        prior = self.current_claim(key)
        net = self._net_observation_score(key)
        claim = Claim.create(
            key=key,
            object_=object_,
            status=status,
            confidence=_confidence_band(net),
            supersedes=prior.id if prior else None,
        )
        self.claims.append(claim)
        self.claim_subgraph[key] = subgraph
        if category is not None:
            self.claim_category[key] = category
        if security_boundary is not None:
            self.claim_boundary[key] = security_boundary
        self._update_hypotheses_for_claim(key, status)
        return claim

    def _net_observation_score(self, key: str) -> int:
        supports = sum(1 for o in self.observations if key in o.supports)
        contradicts = sum(1 for o in self.observations if key in o.contradicts)
        return supports - contradicts

    def _recompute_confidence(self, key: str) -> None:
        prior = self.current_claim(key)
        if prior is None:
            # An Observation arrived referencing a key with no Claim yet --
            # hypothesize it (Section 14, Step 2: first Observation creates
            # a hypothesized Claim at low confidence).
            self.assert_claim(key, object_="true", status=ClaimStatus.HYPOTHESIZED)
            return
        net = self._net_observation_score(key)
        band = _confidence_band(net)
        if band == prior.confidence:
            return  # no-op: avoid noisy no-op claim versions
        claim = Claim.create(
            key=key,
            object_=prior.object,
            status=prior.status,
            confidence=band,
            supersedes=prior.id,
        )
        self.claims.append(claim)

    # -- operator (self) graph -------------------------------------------
    def record_operator_execution(self, operator_id: str, success: bool) -> None:
        stats = self.operator_stats.setdefault(operator_id, OperatorStats())
        stats.executions += 1
        if success:
            stats.successes += 1
        else:
            stats.failures += 1

    # -- views -------------------------------------------------------------
    def defender_claims(self) -> list[Claim]:
        keys = {k for k, sg in self.claim_subgraph.items() if sg == SUBGRAPH_DEFENDER}
        return [c for c in self.claims if c.key in keys]

    def target_claims(self) -> list[Claim]:
        keys = {k for k, sg in self.claim_subgraph.items() if sg == SUBGRAPH_TARGET}
        return [c for c in self.claims if c.key in keys]

    def size(self) -> int:
        """Graph size (Claims + Observations), used for the Figure 14.1-style
        growth trace."""
        return len(self.claims) + len(self.observations)

    def confirmed_boundary_crossings(self) -> dict[str, str]:
        """claim key -> security_boundary tag, for every CURRENTLY-CONFIRMED
        claim that has one (see aginiti/graph/security_boundary.py). Claims
        with no tag (untagged operators -- most of the repo today, by
        design; see that module's docstring) are simply absent, not
        defaulted to a guessed level."""
        from aginiti.graph.security_boundary import BOUNDARY_UNSPECIFIED
        out = {}
        for key, level in self.claim_boundary.items():
            claim = self.current_claim(key)
            if claim is not None and claim.status == ClaimStatus.CONFIRMED and level != BOUNDARY_UNSPECIFIED:
                out[key] = level
        return out

    def highest_boundary_crossed(self) -> str | None:
        """The single most severe security_boundary level among every
        currently-confirmed, tagged claim -- None if nothing tagged has
        been confirmed (an honest "not classified", never a fabricated
        floor). This is the headline number a Target Profile or report can
        show: "the deepest boundary this campaign is confirmed to have
        crossed.\""""
        from aginiti.graph.security_boundary import highest_level
        return highest_level(self.confirmed_boundary_crossings().values())
